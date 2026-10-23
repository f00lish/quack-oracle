#pragma once

#include "oracle_scanner/session.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

struct TtcDescribeInfo {
    std::vector<OracleColumn> columns;
    size_t bytes_consumed = 0;
};

// Decodes one DESCRIBE_INFO (type 16) prefix. The input may contain later TTC
// messages; bytes_consumed identifies the first byte after its descriptor.
// A legacy session is one that speaks the 11.2 dialect: its describe
// response has a shorter column descriptor than the modern one.
TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message,
                                            uint8_t ttc_field_version = 12,
                                            bool legacy_session = false);

} // namespace oracle_scanner
