#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_dialect.hpp"

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
//
// The dialect is the session's, and it is passed as ONE value rather than a
// flag: the describe response differs between the two dialects in more than
// one way (the OACCOLID field, and the scale width, which only the legacy
// one needs to be searched for), and a single value keeps those decisions
// together instead of spread over loose parameters.
TtcDescribeInfo DecodeTtcDescribeInfoPrefix(const std::vector<uint8_t> &message,
                                            uint8_t ttc_field_version = 12,
                                            TtcDialect dialect = TtcDialect{});

} // namespace oracle_scanner
