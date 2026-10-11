#pragma once

#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_lob.hpp"

#include <algorithm>
#include <limits>
#include <optional>

namespace oracle_scanner {

// Preparation only: no request encoder or row decoder produces this yet.
// Character data is normalized to UTF-16BE by the future decoder. Lengths
// and offsets then count UTF-16 units; binary data counts bytes. NULL is a
// disengaged optional, whereas a present zero-length value is an empty LOB.
struct OracleLobPrefetch {
    bool character = false;
    uint64_t total_units = 0;
    uint64_t prefix_units = 0;
    std::vector<uint8_t> prefix;
    std::vector<uint8_t> locator;
};

// The owner must hold its session call lock around this entire operation.
// The explicit content budget is a caller policy, not a new native default.
// Metadata supplies total_units, so neither GET_LENGTH nor a read at EOF is
// needed. Transport errors escape immediately; there is no automatic replay.
template <class Read>
std::optional<std::vector<uint8_t>> MaterializePrefetchedOracleLob(
    const std::optional<OracleLobPrefetch> &value, size_t maximum_prefix_bytes,
    size_t maximum_content_bytes, Read read) {
    constexpr size_t MAX_PREFIX_BYTES = 65536;
    constexpr size_t MAX_LOCATOR_BYTES = 4096;
    if (maximum_prefix_bytes == 0 || maximum_prefix_bytes > MAX_PREFIX_BYTES || maximum_content_bytes == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle LOB prefetch budgets are invalid");
    }
    if (!value) {
        return std::nullopt;
    }
    const auto &lob = *value;
    const uint64_t bytes_per_unit = lob.character ? 2 : 1;
    if (lob.prefix.size() > maximum_prefix_bytes || lob.locator.size() > MAX_LOCATOR_BYTES ||
        lob.total_units > maximum_content_bytes / bytes_per_unit) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle LOB prefetch exceeds allocation bounds");
    }
    if (lob.prefix_units > lob.total_units || lob.prefix_units > maximum_prefix_bytes / bytes_per_unit ||
        lob.prefix.size() != lob.prefix_units * bytes_per_unit ||
        (lob.prefix_units < lob.total_units && lob.locator.empty())) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle LOB prefetch metadata disagrees with content");
    }
    std::vector<uint8_t> content;
    if (lob.total_units > content.max_size() / bytes_per_unit) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle LOB content exceeds allocation bounds");
    }
    // Do not reserve the total reported size. Grow only after validating each
    // response, so an early failure does not allocate the entire long value.
    content = lob.prefix;
    const uint64_t chunk_units = lob.character ? 32767 : 65536;
    uint64_t served = lob.prefix_units;
    while (served < lob.total_units) {
        const auto requested = (std::min)(lob.total_units - served, chunk_units);
        const auto response = read(lob.locator, served + 1, requested);
        if (response.amount > requested || response.data.size() != response.amount * bytes_per_unit) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle LOB remainder returned an invalid amount");
        }
        if (response.amount == 0) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle LOB ended before its prefetched length");
        }
        content.insert(content.end(), response.data.begin(), response.data.end());
        served += response.amount;
    }
    return content;
}

} // namespace oracle_scanner
