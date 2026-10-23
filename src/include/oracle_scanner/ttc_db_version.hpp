#pragma once

#include "oracle_scanner/byte_buffer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// The function code of the database-version request. It is not a TTC message
// type: the request is a TTC FUNCTION call whose code is 0x3B.
constexpr uint8_t TTC_FUNCTION_DB_VERSION = 59;

// What the server reports about its own version. The text is the banner the
// server prints, and the number is the packed version the server derives from
// it.
struct TtcDbVersion {
    std::string info;
    uint32_t number = 0;
};

// Builds the request that asks the server for its version.
//
// Every official client sends this right after the logon completes: go-ora
// calls it from its connect path, and the JDBC driver sends the same request
// before its first statement. A legacy (11.2) listener expects it -- it
// answers the first statement without one with an internal conversion error
// instead of the statement's own result.
//
// The body is the go-ora form: a function call, a one-byte option, the
// 0x100 code, and two more one-byte options.
std::vector<uint8_t> EncodeTtcDbVersionRequest(uint8_t sequence);

// Decodes the server's answer: a TTC PARAMETER message carrying the banner
// as a length-prefixed value, followed by the packed version number.
//
// A legacy (11.2) listener states the length of a long value as one raw
// byte rather than as a universal integer, so the caller says which form the
// session uses.
TtcDbVersion DecodeTtcDbVersionResponse(const std::vector<uint8_t> &message,
                                        TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);

} // namespace oracle_scanner
