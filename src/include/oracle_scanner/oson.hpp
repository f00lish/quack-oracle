#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// Bounds on what one OSON image may expand to. An image is a compact tree, and
// a small one can describe a very large document (shared subtrees, long
// arrays of the same node), so every one of these is checked before the output
// grows rather than after.
struct OsonLimits {
    size_t maximum_output_bytes = size_t {256} << 20U;
    uint32_t maximum_depth = 512;
    uint64_t maximum_nodes = uint64_t {64} << 20U;
};

// Decodes the binary form Oracle stores a JSON column in (OSON, "FF 4A 5A"
// magic) into JSON text. Objects keep the order the image holds their fields
// in. Oracle's non-JSON scalars come out the way JSON_SERIALIZE prints them:
// timestamps as ISO 8601 strings, RAW as an upper-case hex string, intervals as
// ISO 8601 durations, BINARY_DOUBLE and BINARY_FLOAT as numbers (infinities
// and NaN as the strings "Inf", "-Inf" and "Nan"). NUMBER keeps every digit.
//
// Throws ProtocolError: TRUNCATED or MALFORMED for a damaged image,
// LIMIT_EXCEEDED past OsonLimits, UNSUPPORTED for a layout or node type this
// decoder has not been shown rather than a guess at it.
std::string DecodeOsonToJson(const uint8_t *data, size_t size, const OsonLimits &limits = OsonLimits());
std::string DecodeOsonToJson(const std::vector<uint8_t> &image, const OsonLimits &limits = OsonLimits());

} // namespace oracle_scanner
