#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TNS_LONG_LENGTH_INDICATOR = 254;
constexpr uint8_t TNS_NULL_LENGTH_INDICATOR = 255;
constexpr size_t TNS_MAX_SHORT_LENGTH = 252;

// How a session states the length of each piece of a long value. Oracle 19c
// and later state it as a universal integer; the 11.2 dialect states it as
// one raw byte, which is what the "fe 40 <64 bytes> 20 <32 bytes>" form in
// a legacy challenge is.
enum class TtcChunkEncoding {
    UniversalInteger,
    RawByte,
};

class ByteReader {
public:
    ByteReader(const uint8_t *data, size_t size);
    explicit ByteReader(const std::vector<uint8_t> &data);

    size_t Position() const;
    size_t Remaining() const;
    uint8_t ReadByte();
    uint8_t PeekByte() const;
    std::vector<uint8_t> ReadRaw(size_t count);
    void Skip(size_t count);
    uint16_t ReadUInt16BE();
    uint16_t ReadUInt16LE();
    uint32_t ReadUInt32BE();
    uint16_t ReadUB2();
    uint32_t ReadUB4();
    uint64_t ReadUB8();
    // Reads a value whose own length byte may be wider than the width its
    // field is usually called. A compressed universal integer states its own
    // length, and a few fields in a describe response carry one that is far
    // past their usual width -- an 11.2 response has an eighty-one byte one.
    // Those fields are read with this, so the width a field is normally called
    // stays the limit everywhere else.
    uint32_t ReadUB4Unbounded();

    // The scale of a column in a describe response is a signed value, and the
    // 11.2 listener does not state it in a single fixed width. A NUMBER column
    // whose scale is the float marker -127 is sent one of two ways, and the
    // same server uses both within a session: as a single signed byte
    // (`81` is -127), or as the compressed signed integer go-ora v1 reads for
    // bind-parameter scales (`81 7f` is -127 there too — see
    // network/session.go GetInt64 with compress=true). Which width is in the
    // response cannot be told from the scale field alone, so DecodeColumn
    // carries each candidate through the rest of the descriptor and keeps the
    // one that stays self-consistent. `81 7f` is therefore a scale of -127,
    // not 127: bit 7 of the leading byte is the sign, and the next byte is the
    // magnitude, which is what go-ora does and what the byte-aligned rest of
    // the column confirms.
    int64_t ReadSignedUniversal(size_t maximum_bytes);
    std::optional<std::vector<uint8_t>> ReadLengthPrefixed(size_t maximum_size,
                                                            TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);
    std::string ReadNullTerminated(size_t maximum_size);

private:
    uint64_t ReadUniversal(size_t maximum_bytes);
    // The length of one piece of a long value. A modern session states it as
    // a universal integer; the 11.2 dialect states it as one raw byte.
    size_t ReadChunkLength(TtcChunkEncoding chunk_encoding);

    const uint8_t *data;
    size_t size;
    size_t position;
};

class ByteWriter {
public:
    ByteWriter &WriteByte(uint8_t value);
    ByteWriter &WriteUInt16BE(uint16_t value);
    ByteWriter &WriteUInt16LE(uint16_t value);
    ByteWriter &WriteUInt32BE(uint32_t value);
    ByteWriter &WriteRaw(const uint8_t *value, size_t size);
    ByteWriter &WriteRaw(const std::vector<uint8_t> &value);
    ByteWriter &WriteUB2(uint16_t value);
    ByteWriter &WriteUB4(uint32_t value);
    ByteWriter &WriteUB8(uint64_t value);
    ByteWriter &WriteLengthPrefixed(const std::optional<std::vector<uint8_t>> &value);
    ByteWriter &WriteNullTerminated(const std::string &value);

    const std::vector<uint8_t> &Data() const;
    std::vector<uint8_t> Take();

private:
    ByteWriter &WriteUniversal(uint64_t value, size_t maximum_bytes);
    std::vector<uint8_t> data;
};

} // namespace oracle_scanner
