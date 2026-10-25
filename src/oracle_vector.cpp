#include "oracle_scanner/oracle_vector.hpp"

#include "oracle_scanner/protocol_error.hpp"

#include <cstring>
#include <string>

namespace oracle_scanner {
namespace {

// db  version(1)  flags(2)  format(1)  dimensions(4)  [norm(8)]  elements
//
// All big-endian. 0x10 in the flags says the 8-byte norm is present, which it
// was in every image seen, and 0x20 marks a sparse vector. A sparse vector's
// elements are a 2-byte count, that many 4-byte indices, then that many
// values. A floating-point element is stored sign-flipped so that the bytes
// sort as the numbers do: the sign bit set for a positive value, every bit
// inverted for a negative one — the same form BINARY_FLOAT and BINARY_DOUBLE
// use. A BINARY vector's dimension count is in bits.
constexpr uint8_t MAGIC = 0xDB;
constexpr uint16_t FLAG_NORM = 0x0010;
constexpr uint16_t FLAG_SPARSE = 0x0020;
constexpr uint16_t KNOWN_FLAGS = 0x0002 | 0x0004 | FLAG_NORM | FLAG_SPARSE;
constexpr uint8_t MAXIMUM_VERSION = 2;

[[noreturn]] void Fail(ProtocolErrorKind kind, const std::string &what) {
    throw ProtocolError(kind, "VECTOR image " + what);
}

template <class FLOAT, class INTEGER>
FLOAT ReadFloating(const uint8_t *data) {
    INTEGER bits = 0;
    uint8_t bytes[sizeof(INTEGER)];
    std::memcpy(bytes, data, sizeof(bytes));
    if ((bytes[0] & 0x80U) != 0) {
        bytes[0] &= 0x7FU;
    } else {
        for (auto &byte : bytes) {
            byte = static_cast<uint8_t>(~byte);
        }
    }
    for (const auto byte : bytes) {
        bits = static_cast<INTEGER>((bits << 8U) | byte);
    }
    FLOAT result;
    std::memcpy(&result, &bits, sizeof(result));
    return result;
}

// The bytes of a floating-point element as they sort: the sign bit set for a
// positive value, every bit inverted for a negative one.
template <class FLOAT, class INTEGER>
std::vector<uint8_t> SortableFloating(FLOAT value) {
    INTEGER bits;
    std::memcpy(&bits, &value, sizeof(bits));
    std::vector<uint8_t> bytes(sizeof(bits));
    for (size_t index = 0; index < bytes.size(); index++) {
        bytes[index] = static_cast<uint8_t>(bits >> (8U * (bytes.size() - 1 - index)));
    }
    if ((bytes[0] & 0x80U) == 0) {
        bytes[0] |= 0x80U;
    } else {
        for (auto &byte : bytes) {
            byte = static_cast<uint8_t>(~byte);
        }
    }
    return bytes;
}
std::vector<uint8_t> SortableFloating(float value) {
    return SortableFloating<float, uint32_t>(value);
}
std::vector<uint8_t> SortableFloating(double value) {
    return SortableFloating<double, uint64_t>(value);
}

uint64_t ReadBigEndian(const uint8_t *data, size_t width) {
    uint64_t value = 0;
    for (size_t index = 0; index < width; index++) {
        value = (value << 8U) | data[index];
    }
    return value;
}

size_t ElementWidth(uint8_t format) {
    switch (format) {
    case ORACLE_VECTOR_FLOAT32:
        return 4;
    case ORACLE_VECTOR_FLOAT64:
        return 8;
    case ORACLE_VECTOR_INT8:
    case ORACLE_VECTOR_BINARY:
        return 1;
    default:
        Fail(ProtocolErrorKind::UNSUPPORTED, "has storage format " + std::to_string(format) + ", which this decoder has not been shown");
    }
}

void ReadElements(OracleVector &vector, const uint8_t *data, size_t count) {
    switch (vector.format) {
    case ORACLE_VECTOR_FLOAT32:
        vector.float32.resize(count);
        for (size_t index = 0; index < count; index++) {
            vector.float32[index] = ReadFloating<float, uint32_t>(data + index * 4);
        }
        break;
    case ORACLE_VECTOR_FLOAT64:
        vector.float64.resize(count);
        for (size_t index = 0; index < count; index++) {
            vector.float64[index] = ReadFloating<double, uint64_t>(data + index * 8);
        }
        break;
    case ORACLE_VECTOR_INT8:
        vector.int8.resize(count);
        for (size_t index = 0; index < count; index++) {
            vector.int8[index] = static_cast<int8_t>(data[index]);
        }
        break;
    default:
        vector.binary.assign(data, data + count);
        break;
    }
}

} // namespace

OracleVector DecodeOracleVector(const uint8_t *data, size_t size) {
    constexpr size_t header_size = 9;
    if (size < header_size) {
        Fail(ProtocolErrorKind::TRUNCATED, "ends inside its header");
    }
    if (data[0] != MAGIC) {
        Fail(ProtocolErrorKind::MALFORMED, "does not start with the VECTOR magic byte");
    }
    if (data[1] > MAXIMUM_VERSION) {
        Fail(ProtocolErrorKind::UNSUPPORTED, "has version " + std::to_string(data[1]) + ", which this decoder has not been shown");
    }
    const auto flags = static_cast<uint16_t>(ReadBigEndian(data + 2, 2));
    if ((flags & ~KNOWN_FLAGS) != 0) {
        Fail(ProtocolErrorKind::UNSUPPORTED, "has flags " + std::to_string(flags) + ", which this decoder has not been shown");
    }
    OracleVector result;
    result.format = data[4];
    result.dimensions = static_cast<uint32_t>(ReadBigEndian(data + 5, 4));
    result.sparse = (flags & FLAG_SPARSE) != 0;
    const size_t width = ElementWidth(result.format);
    if (result.dimensions > ORACLE_VECTOR_MAXIMUM_DIMENSIONS) {
        Fail(ProtocolErrorKind::LIMIT_EXCEEDED, "declares more dimensions than a VECTOR can have");
    }
    if (result.format == ORACLE_VECTOR_BINARY && result.dimensions % 8 != 0) {
        Fail(ProtocolErrorKind::MALFORMED, "has a BINARY vector whose bit count is not a whole number of bytes");
    }
    size_t position = header_size;
    if ((flags & FLAG_NORM) != 0) {
        if (size - position < 8) {
            Fail(ProtocolErrorKind::TRUNCATED, "ends inside its norm");
        }
        position += 8;
    }
    if (!result.sparse) {
        const size_t count = result.format == ORACLE_VECTOR_BINARY ? result.dimensions / 8 : result.dimensions;
        if (size - position != count * width) {
            Fail(size - position < count * width ? ProtocolErrorKind::TRUNCATED : ProtocolErrorKind::MALFORMED,
                 "has " + std::to_string(size - position) + " bytes of elements where " + std::to_string(count * width) +
                     " were declared");
        }
        ReadElements(result, data + position, count);
        return result;
    }
    if (result.format == ORACLE_VECTOR_BINARY) {
        Fail(ProtocolErrorKind::UNSUPPORTED, "is a sparse BINARY vector, which Oracle does not have");
    }
    if (size - position < 2) {
        Fail(ProtocolErrorKind::TRUNCATED, "ends inside its sparse element count");
    }
    const size_t count = static_cast<size_t>(ReadBigEndian(data + position, 2));
    position += 2;
    if (count > result.dimensions) {
        Fail(ProtocolErrorKind::MALFORMED, "has more sparse elements than dimensions");
    }
    if (size - position != count * (4 + width)) {
        Fail(size - position < count * (4 + width) ? ProtocolErrorKind::TRUNCATED : ProtocolErrorKind::MALFORMED,
             "has the wrong number of bytes for its sparse elements");
    }
    result.indices.resize(count);
    for (size_t index = 0; index < count; index++) {
        const auto position_in_vector = static_cast<uint32_t>(ReadBigEndian(data + position + index * 4, 4));
        if (position_in_vector >= result.dimensions || (index != 0 && position_in_vector <= result.indices[index - 1])) {
            Fail(ProtocolErrorKind::MALFORMED, "has sparse indices that are out of range or not increasing");
        }
        result.indices[index] = position_in_vector;
    }
    ReadElements(result, data + position + count * 4, count);
    return result;
}

OracleVector DecodeOracleVector(const std::vector<uint8_t> &image) {
    return DecodeOracleVector(image.data(), image.size());
}

std::vector<uint8_t> EncodeOracleVector(const OracleVector &vector) {
    const size_t width = ElementWidth(vector.format);
    size_t count;
    switch (vector.format) {
    case ORACLE_VECTOR_FLOAT32:
        count = vector.float32.size();
        break;
    case ORACLE_VECTOR_FLOAT64:
        count = vector.float64.size();
        break;
    case ORACLE_VECTOR_INT8:
        count = vector.int8.size();
        break;
    default:
        count = vector.binary.size();
        break;
    }
    const bool binary = vector.format == ORACLE_VECTOR_BINARY;
    if (vector.dimensions > ORACLE_VECTOR_MAXIMUM_DIMENSIONS ||
        (vector.sparse && (binary || vector.indices.size() != count || count > 65535 || count > vector.dimensions)) ||
        (!vector.sparse && (binary ? count * 8 != vector.dimensions : count != vector.dimensions))) {
        Fail(ProtocolErrorKind::MALFORMED, "to be written disagrees with its own dimension count");
    }
    std::vector<uint8_t> image;
    image.reserve(17 + count * (width + (vector.sparse ? 4 : 0)));
    const auto put = [&](uint64_t value, size_t bytes) {
        for (size_t index = 0; index < bytes; index++) {
            image.push_back(static_cast<uint8_t>(value >> (8U * (bytes - 1 - index))));
        }
    };
    image.push_back(MAGIC);
    image.push_back(vector.sparse ? 2 : binary ? 1 : 0);
    put(vector.sparse ? (FLAG_NORM | FLAG_SPARSE | 0x0002) : binary ? FLAG_NORM : (FLAG_NORM | 0x0002), 2);
    image.push_back(vector.format);
    put(vector.dimensions, 4);
    image.insert(image.end(), 8, 0); // the norm, which the server computes
    if (vector.sparse) {
        put(count, 2);
        uint32_t previous = 0;
        for (size_t index = 0; index < count; index++) {
            if (vector.indices[index] >= vector.dimensions || (index != 0 && vector.indices[index] <= previous)) {
                Fail(ProtocolErrorKind::MALFORMED, "to be written has sparse indices that are out of range or not increasing");
            }
            previous = vector.indices[index];
            put(vector.indices[index], 4);
        }
    }
    const auto put_floating = [&](const std::vector<uint8_t> &sortable) { image.insert(image.end(), sortable.begin(), sortable.end()); };
    switch (vector.format) {
    case ORACLE_VECTOR_FLOAT32:
        for (const auto element : vector.float32) {
            put_floating(SortableFloating(element));
        }
        break;
    case ORACLE_VECTOR_FLOAT64:
        for (const auto element : vector.float64) {
            put_floating(SortableFloating(element));
        }
        break;
    case ORACLE_VECTOR_INT8:
        for (const auto element : vector.int8) {
            image.push_back(static_cast<uint8_t>(element));
        }
        break;
    default:
        image.insert(image.end(), vector.binary.begin(), vector.binary.end());
        break;
    }
    return image;
}

} // namespace oracle_scanner
