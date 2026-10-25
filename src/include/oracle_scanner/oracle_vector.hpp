#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

// The storage formats of a VECTOR, numbered as the server's describe numbers
// them.
constexpr uint8_t ORACLE_VECTOR_FLOAT32 = 2;
constexpr uint8_t ORACLE_VECTOR_FLOAT64 = 3;
constexpr uint8_t ORACLE_VECTOR_INT8 = 4;
constexpr uint8_t ORACLE_VECTOR_BINARY = 5;

// Bits of OracleColumn::vector_flags, which the describe sends.
constexpr uint8_t ORACLE_VECTOR_COLUMN_FLEXIBLE_DIMENSIONS = 0x01;
constexpr uint8_t ORACLE_VECTOR_COLUMN_SPARSE = 0x02;

// Oracle allows up to 65535 dimensions; a BINARY vector counts bits.
constexpr size_t ORACLE_VECTOR_MAXIMUM_DIMENSIONS = 65535;

// One decoded VECTOR value. Exactly one of the arrays holds the elements,
// the one `format` names. A BINARY vector holds its bits packed, eight to a
// byte, so `binary.size()` is `dimensions / 8`. A sparse vector holds only its
// non-zero elements, at `indices`; `dimensions` is its full length.
struct OracleVector {
    uint8_t format = 0;
    uint32_t dimensions = 0;
    bool sparse = false;
    std::vector<uint32_t> indices;
    std::vector<float> float32;
    std::vector<double> float64;
    std::vector<int8_t> int8;
    std::vector<uint8_t> binary;
};

// Decodes the image a VECTOR column's locator holds. Throws ProtocolError:
// TRUNCATED or MALFORMED for a damaged image, UNSUPPORTED for a header this
// decoder has not been shown.
OracleVector DecodeOracleVector(const uint8_t *data, size_t size);
OracleVector DecodeOracleVector(const std::vector<uint8_t> &image);

// The image a bind carries, in the form python-oracledb Thin sends: a norm
// field of zeros for the server to fill in, and the version and flags it uses
// for a dense, a BINARY and a sparse vector. `float32`, `float64`, `int8` or
// `binary` (whichever `format` names) and, for a sparse vector, `indices` must
// be set and agree with `dimensions`; anything else throws MALFORMED.
std::vector<uint8_t> EncodeOracleVector(const OracleVector &vector);

} // namespace oracle_scanner
