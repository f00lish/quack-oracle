#pragma once

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/ttc_describe.hpp"

#include <cstdint>
#include <vector>

namespace oracle_scanner {

// Decodes a DESCRIBE_INFO (type 16) prefix from a LEGACY (11.2 and earlier)
// listener.
//
// It is a separate implementation, not a variant of the modern one: the
// legacy response has no OACCOLID, and its NUMBER column's scale is not
// stated in a fixed width, so the reader has to search for the width the
// server used. Keeping that search out of the modern reader is what keeps
// the modern path byte-identical to what it was before 11.2 support existed.
//
// `chunk_encoding` says how the session states the length of a long value:
// a universal integer on a modern session, one raw byte on a legacy (11.2)
// one. The version bytes and the column names are such values.
TtcDescribeInfo DecodeTtcLegacyDescribeInfoPrefix(const std::vector<uint8_t> &message,
                                                   uint8_t ttc_field_version = 12,
                                                   TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);

} // namespace oracle_scanner
