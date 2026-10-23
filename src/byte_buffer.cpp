#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <limits>
#include <sstream>

namespace oracle_scanner {

static ProtocolError Truncated(size_t requested, size_t remaining) {
    std::ostringstream message;
    message << "TTC message is truncated: need " << requested << " bytes, have " << remaining;
    return ProtocolError(ProtocolErrorKind::TRUNCATED, message.str());
}

ByteReader::ByteReader(const uint8_t *data_p, size_t size_p) : data(data_p), size(size_p), position(0) {
}

ByteReader::ByteReader(const std::vector<uint8_t> &data_p) : ByteReader(data_p.data(), data_p.size()) {
}

size_t ByteReader::Position() const {
    return position;
}

size_t ByteReader::Remaining() const {
    return size - position;
}

uint8_t ByteReader::ReadByte() {
    if (Remaining() == 0) {
        throw Truncated(1, 0);
    }
    return data[position++];
}

uint8_t ByteReader::PeekByte() const {
    if (Remaining() == 0) {
        throw Truncated(1, 0);
    }
    return data[position];
}

std::vector<uint8_t> ByteReader::ReadRaw(size_t count) {
    if (count > Remaining()) {
        throw Truncated(count, Remaining());
    }
    std::vector<uint8_t> result(data + position, data + position + count);
    position += count;
    return result;
}

void ByteReader::Skip(size_t count) {
    (void)ReadRaw(count);
}

uint16_t ByteReader::ReadUInt16BE() {
    auto bytes = ReadRaw(2);
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8U) | bytes[1]);
}

uint16_t ByteReader::ReadUInt16LE() {
    auto bytes = ReadRaw(2);
    return static_cast<uint16_t>((static_cast<uint16_t>(bytes[1]) << 8U) | bytes[0]);
}

uint32_t ByteReader::ReadUInt32BE() {
    auto bytes = ReadRaw(4);
    return (static_cast<uint32_t>(bytes[0]) << 24U) | (static_cast<uint32_t>(bytes[1]) << 16U) |
           (static_cast<uint32_t>(bytes[2]) << 8U) | bytes[3];
}

uint64_t ByteReader::ReadUniversal(size_t maximum_bytes) {
    auto length = ReadByte();
    if ((length & 0x80U) != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "negative universal integer is not valid here");
    }
    if (length > maximum_bytes) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "universal integer exceeds its declared width");
    }
    uint64_t result = 0;
    for (size_t index = 0; index < length; index++) {
        result = (result << 8U) | ReadByte();
    }
    return result;
}

uint32_t ByteReader::ReadUB4() {
    return static_cast<uint32_t>(ReadUniversal(4));
}

uint16_t ByteReader::ReadUB2() {
    return static_cast<uint16_t>(ReadUniversal(2));
}

uint64_t ByteReader::ReadUB8() {
    return ReadUniversal(8);
}

// A zero-length TTC value is Oracle's NULL: the database does not distinguish
// an empty character value from NULL, and both the short and the chunked
// length forms can express one. The decoder therefore has a single NULL
// representation, `std::nullopt`, and never yields a present-but-empty value.
// ByteWriter::WriteLengthPrefixed is the symmetric half and collapses an empty
// value to the NULL indicator.
std::optional<std::vector<uint8_t>> ByteReader::ReadLengthPrefixed(size_t maximum_size, TtcChunkEncoding chunk_encoding) {
    auto first = ReadByte();
    if (first == 0 || first == TNS_NULL_LENGTH_INDICATOR) {
        return std::nullopt;
    }
    if (first != TNS_LONG_LENGTH_INDICATOR) {
        if (first > maximum_size) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC value exceeds configured limit");
        }
        return ReadRaw(first);
    }

    std::vector<uint8_t> result;
    while (true) {
        auto chunk_size = ReadChunkLength(chunk_encoding);
        if (chunk_size == 0) {
            if (result.empty()) {
                return std::nullopt;
            }
            return result;
        }
        if (chunk_size > maximum_size - result.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "chunked TTC value exceeds configured limit");
        }
        auto chunk = ReadRaw(chunk_size);
        result.insert(result.end(), chunk.begin(), chunk.end());
    }
}

// The length of one piece of a long value. A modern session states it as a
// universal integer, whose first byte is the width of the number that follows.
// The 11.2 dialect states it as a single raw byte instead, which is what the
// "fe 40 <64 bytes> 20 <32 bytes>" form of a legacy challenge is.
//
// The two encodings are read strictly. A byte that cannot be a universal
// integer width is NOT treated as a raw length here: that guess used to make
// a legacy frame readable through the modern path, but it read it *wrongly*
// whenever a legacy chunk was four bytes or shorter (a width byte of 2 is a
// valid universal integer width, so the reader would swallow the next four
// bytes as the length). Reading the frame the wrong way round has to fail
// loudly instead: the caller picks the encoding from the session's own
// legacy marker, and a wrong pick is a bug worth seeing.
size_t ByteReader::ReadChunkLength(TtcChunkEncoding chunk_encoding) {
    if (chunk_encoding == TtcChunkEncoding::RawByte) {
        return ReadByte();
    }
    return static_cast<size_t>(ReadUB4());
}

std::string ByteReader::ReadNullTerminated(size_t maximum_size) {
    std::string result;
    while (result.size() <= maximum_size) {
        auto byte = ReadByte();
        if (byte == 0) {
            return result;
        }
        result.push_back(static_cast<char>(byte));
    }
    throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "null-terminated TTC value exceeds configured limit");
}

ByteWriter &ByteWriter::WriteByte(uint8_t value) {
    data.push_back(value);
    return *this;
}

ByteWriter &ByteWriter::WriteUInt16BE(uint16_t value) {
    data.push_back(static_cast<uint8_t>(value >> 8U));
    data.push_back(static_cast<uint8_t>(value));
    return *this;
}

ByteWriter &ByteWriter::WriteUInt16LE(uint16_t value) {
    data.push_back(static_cast<uint8_t>(value));
    data.push_back(static_cast<uint8_t>(value >> 8U));
    return *this;
}

ByteWriter &ByteWriter::WriteUInt32BE(uint32_t value) {
    data.push_back(static_cast<uint8_t>(value >> 24U));
    data.push_back(static_cast<uint8_t>(value >> 16U));
    data.push_back(static_cast<uint8_t>(value >> 8U));
    data.push_back(static_cast<uint8_t>(value));
    return *this;
}

ByteWriter &ByteWriter::WriteRaw(const uint8_t *value, size_t value_size) {
    data.insert(data.end(), value, value + value_size);
    return *this;
}

ByteWriter &ByteWriter::WriteRaw(const std::vector<uint8_t> &value) {
    return WriteRaw(value.data(), value.size());
}

ByteWriter &ByteWriter::WriteUniversal(uint64_t value, size_t maximum_bytes) {
    if (value == 0) {
        return WriteByte(0);
    }
    size_t bytes = 1;
    while (bytes < maximum_bytes && value >= (uint64_t(1) << (bytes * 8U))) {
        bytes++;
    }
    WriteByte(static_cast<uint8_t>(bytes));
    for (size_t index = bytes; index > 0; index--) {
        WriteByte(static_cast<uint8_t>(value >> ((index - 1) * 8U)));
    }
    return *this;
}

ByteWriter &ByteWriter::WriteUB4(uint32_t value) {
    return WriteUniversal(value, 4);
}

ByteWriter &ByteWriter::WriteUB2(uint16_t value) {
    return WriteUniversal(value, 2);
}

ByteWriter &ByteWriter::WriteUB8(uint64_t value) {
    return WriteUniversal(value, 8);
}

// Empty and NULL share one wire form; see ByteReader::ReadLengthPrefixed for
// the decoding half of that policy. An empty VARCHAR2 bind therefore reaches
// Oracle as NULL, which is what Oracle itself does with `''`.
ByteWriter &ByteWriter::WriteLengthPrefixed(const std::optional<std::vector<uint8_t>> &value) {
    if (!value.has_value() || value->empty()) {
        return WriteByte(TNS_NULL_LENGTH_INDICATOR);
    }
    if (value->size() <= TNS_MAX_SHORT_LENGTH) {
        WriteByte(static_cast<uint8_t>(value->size()));
        return WriteRaw(*value);
    }
    WriteByte(TNS_LONG_LENGTH_INDICATOR);
    size_t offset = 0;
    constexpr size_t chunk_size = 0x8000;
    while (offset < value->size()) {
        auto count = (std::min)(chunk_size, value->size() - offset);
        WriteUB4(static_cast<uint32_t>(count));
        WriteRaw(value->data() + offset, count);
        offset += count;
    }
    return WriteUB4(0);
}

ByteWriter &ByteWriter::WriteNullTerminated(const std::string &value) {
    WriteRaw(reinterpret_cast<const uint8_t *>(value.data()), value.size());
    return WriteByte(0);
}

const std::vector<uint8_t> &ByteWriter::Data() const {
    return data;
}

std::vector<uint8_t> ByteWriter::Take() {
    return std::move(data);
}

} // namespace oracle_scanner
