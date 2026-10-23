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
// The legacy (11.2) session describes its columns in a different shape: its
// continuation flag is four bytes rather than eight, and it has no oaccolid,
// nullable or V7 name length. The caller must say which shape applies.
TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message,
                                            uint8_t ttc_field_version = 12, bool legacy_session = false);

} // namespace oracle_scanner
