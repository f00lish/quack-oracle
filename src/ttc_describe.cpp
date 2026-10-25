#include "oracle_scanner/ttc_describe.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_dialect.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <limits>
#include <vector>

namespace oracle_scanner {

namespace {

constexpr uint8_t TTC_MESSAGE_DESCRIBE_INFO = 16;
constexpr uint32_t MAX_COLUMNS = 4096;
constexpr uint32_t MAX_METADATA_BYTES = 1U << 20U;

void ReadDeclaredBytes(ByteReader &reader, TtcChunkEncoding chunk_encoding) {
    const auto declared = reader.ReadUB4();
    if (declared == 0) {
        return;
    }
    if (declared > MAX_METADATA_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC describe metadata field is too large");
    }
    // Bounded, not stated: see ReadDeclaredText below and ttc_parameter.cpp.
    const auto value = reader.ReadLengthPrefixed(declared, chunk_encoding);
    if (!value) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe metadata field length disagrees with payload");
    }
}

std::string ReadDeclaredText(ByteReader &reader, TtcChunkEncoding chunk_encoding) {
    const auto declared = reader.ReadUB4();
    if (declared == 0) {
        return {};
    }
    if (declared > MAX_METADATA_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC describe identifier is too large");
    }
    // As in ttc_parameter.cpp, the declared size is an upper bound stated in the
    // character set this client requested, not the length of what follows: on a
    // database that is not AL32UTF8 the server sizes a column name for three
    // bytes per character and then sends its actual ones.
    const auto value = reader.ReadLengthPrefixed(declared, chunk_encoding);
    if (!value) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe identifier length disagrees with payload");
    }
    return {value->begin(), value->end()};
}

// The scale of a NUMBER column in an 11.2 describe response is the float
// marker -127, and the listener encodes it one of two ways. The single-byte
// form sends -127 directly: `81`. The compressed form sends the signed
// universal integer go-ora v1 reads (network/session.go GetInt64 with
// compress=true), where the leading byte bit 7 is the sign and its low
// seven bits are the width of the magnitude that follows: `81 7f` is -127.
// The two encodings carry the same value, and the same server uses both
// within one session, so the width cannot be decided from the scale field on
// its own. DecodeColumnWithScale therefore runs each candidate through the
// rest of the column, and DecodeColumnsAndTrailer backtracks across the
// columns and the trailer to keep the candidate that lets the whole
// descriptor stay self-consistent.
//
// A wrong choice desynchronizes the reader by one byte and the rest of the
// column stops decoding: maximum_size is the next field and it is a universal
// integer whose width must be at most four, so reading it from the wrong byte
// throws "universal integer exceeds its declared width". That is the failure
// the old one-size reader produced at column 2 of the live six-column
// response: it read `81 01` as a two-byte scale of 1, then tried to read
// maximum_size from `16` (22) and refused the width.

struct ScaleCandidate {
    int64_t value = 0;
};

// Read the scale field after type/flags/precision have been consumed.
// OneByte: a single signed byte — the majority form in the live corpus.
// Compressed: the signed universal integer go-ora v1 reads (bit 7 = sign,
// low 7 bits = magnitude width). `81 7f` is -127 either way.
int64_t ReadScaleOneByte(ByteReader &reader) {
    return static_cast<int8_t>(reader.ReadByte());
}

int64_t ReadScaleCompressed(ByteReader &reader) {
    return reader.ReadSignedUniversal(1);
}

using ScaleReader = int64_t (*)(ByteReader &);

const ScaleReader SCALE_READERS[] = {ReadScaleOneByte, ReadScaleCompressed};

OracleColumn DecodeColumnWithScale(ByteReader &reader, uint8_t field_version, TtcDialect dialect,
                                   TtcChunkEncoding chunk_encoding, const ScaleCandidate &scale,
                                   uint8_t oracle_type, int8_t precision) {
    OracleColumn column;
    column.oracle_type = oracle_type;
    column.precision = precision;
    column.scale = static_cast<int16_t>(scale.value);
    const auto maximum_size = reader.ReadUB4();
    reader.ReadUB4(); // maximum array elements
    reader.ReadUB8(); // continuation flags
    ReadDeclaredBytes(reader, chunk_encoding); // object id
    reader.ReadUB2(); // version
    column.character_set_id = reader.ReadUB2(); // character set id
    column.character_set_form = reader.ReadByte();
    const auto size = reader.ReadUB4();
    // TTIPRO's server version is not the version gate for OALL8 describe
    // metadata. A live 19c response reports TTIPRO version 6 yet includes
    // oaccolid followed by nullable. This is also the shape emitted after the
    // OALL8 request used by python-oracledb, so retain it unconditionally for
    // the supported modern TTC execution profile.
    //
    // An 11.2 listener does not send oaccolid at all: its describe response
    // goes straight from the size field to nullable. Reading the field there
    // shifts every later field by two bytes, and the name that comes out is
    // the declared length of the text rather than the text itself.
    if (dialect.describe_has_oaccolid) {
        reader.ReadUB4(); // oaccolid
    }
    column.nullable = reader.ReadByte() != 0;
    reader.ReadByte(); // V7 name length
    column.name = ReadDeclaredText(reader, chunk_encoding);
    ReadDeclaredText(reader, chunk_encoding); // schema
    ReadDeclaredText(reader, chunk_encoding); // type name
    reader.ReadUB2(); // column position
    reader.ReadUB4(); // UDS flags
    if (field_version >= 17) {
        ReadDeclaredText(reader, chunk_encoding); // domain schema
        ReadDeclaredText(reader, chunk_encoding); // domain name
    }
    if (field_version >= 20) {
        const auto annotation_size = reader.ReadUB4();
        if (annotation_size != 0) {
            throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "TTC describe annotations are not yet supported");
        }
    }
    if (field_version >= 24) {
        column.vector_dimensions = reader.ReadUB4();
        column.vector_format = reader.ReadByte();
        column.vector_flags = reader.ReadByte();
    }
    column.byte_width = column.oracle_type == 23 ? maximum_size : size;
    // The declared maximum, not the size field, is what says whether the column
    // carries bytes at all: NUMBER and DATE report size 0 while still sending a
    // value, and only a zero maximum means nothing is sent. A REF CURSOR is
    // never a ROW_DATA column, so it is excluded rather than reasoned about.
    column.omitted_from_row_data = maximum_size == 0 && column.oracle_type != 102 && !IsOracleLongType(column.oracle_type);
    if (column.oracle_type == 102) {
        column.byte_width = 4;
    }
    return column;
}

// Decodes the columns and the trailer, backtracking across the scale
// candidates when a column's choice does not lead to a self-consistent
// descriptor. `explored` bounds the search so a malformed response cannot make
// it diverge. The first scale candidate that lets every remaining column and
// the trailer decode is kept.
bool DecodeColumnsAndTrailer(const std::vector<uint8_t> &message, uint8_t field_version, TtcDialect dialect,
                             TtcChunkEncoding chunk_encoding, ByteReader &reader, uint32_t column_count,
                             std::vector<OracleColumn> &columns, uint32_t &explored) {
    if (columns.size() == column_count) {
        try {
            ReadDeclaredBytes(reader, chunk_encoding); // current date
            // The four fields between the two blocks are read without a width
            // limit: the first of them in an 11.2 response states a length of
            // eighty-one bytes, and a four-byte limit would refuse the response
            // that the server sent in good faith.
            reader.ReadUB4Unbounded();
            reader.ReadUB4Unbounded();
            reader.ReadUB4Unbounded();
            reader.ReadUB4Unbounded();
            ReadDeclaredBytes(reader, chunk_encoding); // descriptor tail
        } catch (const ProtocolError &) {
            return false;
        }
        return true;
    }
    if (++explored > 8192) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "TTC describe did not resolve a scale width within the search budget");
    }
    (void)message;
    for (const auto scale_reader : SCALE_READERS) {
        ByteReader candidate(reader);
        // type, flags, precision come before scale; read them on the
        // candidate so the scale reader sees the correct offset.
        const auto oracle_type = candidate.ReadByte();
        candidate.ReadByte(); // flags
        const auto precision = static_cast<int8_t>(candidate.ReadByte());
        ScaleCandidate scale;
        try {
            scale.value = scale_reader(candidate);
        } catch (const ProtocolError &) {
            continue;
        }
        OracleColumn column;
        try {
            column = DecodeColumnWithScale(candidate, field_version, dialect, chunk_encoding, scale,
                                           oracle_type, precision);
        } catch (const ProtocolError &) {
            continue;
        }
        std::vector<OracleColumn> next_columns = columns;
        next_columns.push_back(std::move(column));
        if (DecodeColumnsAndTrailer(message, field_version, dialect, chunk_encoding, candidate, column_count,
                                    next_columns, explored)) {
            columns = std::move(next_columns);
            reader = candidate;
            return true;
        }
    }
    return false;
}

} // namespace

TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message, uint8_t ttc_field_version,
                                            TtcDialect dialect) {
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_DESCRIBE_INFO) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC DESCRIBE_INFO message");
    }
    // The session's dialect decides how the length of a long value is stated.
    const auto chunk_encoding = dialect.chunk_encoding;
    (void)reader.ReadLengthPrefixed(MAX_METADATA_BYTES, chunk_encoding); // version bytes
    reader.ReadUB4(); // maximum row size
    const auto column_count = reader.ReadUB4();
    if (column_count == 0 || column_count > MAX_COLUMNS) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC describe has an invalid column count");
    }
    reader.ReadByte();
    TtcDescribeInfo result;
    result.columns.reserve(column_count);
    uint32_t explored = 0;
    std::vector<OracleColumn> columns;
    if (!DecodeColumnsAndTrailer(message, ttc_field_version, dialect, chunk_encoding, reader, column_count,
                                columns, explored)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                             "TTC describe column " + std::to_string(columns.size()) + " at offset " +
                                 std::to_string(reader.Position()) + ": no scale width decoded the column");
    }
    result.columns = std::move(columns);
    result.bytes_consumed = reader.Position();
    return result;
}

} // namespace oracle_scanner
