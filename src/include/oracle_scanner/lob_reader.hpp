#pragma once

#include "oracle_scanner/ttc_lob.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include <algorithm>
#include <limits>

namespace oracle_scanner {

// The callbacks use the existing locator READ and GET_LENGTH operations.
// A short first READ is complete. Only a full first chunk needs GET_LENGTH;
// this retains the known-length path for long LOBs and exact chunk boundaries.
template <class Read, class Length>
std::vector<uint8_t> ReadOracleLobContent(bool character, Read read, Length length) {
    const uint64_t chunk_units = character ? 32767 : 65536;
    std::vector<uint8_t> content;
    const auto append = [&](const TtcLobResponse &response, uint64_t requested) {
        if (response.amount > requested ||
            (response.amount == 0 && !response.data.empty()) ||
            (response.amount != 0 && response.data.empty()) ||
            response.data.size() > requested * (character ? 2 : 1)) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle LOB read returned an invalid amount");
        }
        if (response.data.size() > content.max_size() - content.size()) {
            throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "Oracle LOB content exceeds allocation bounds");
        }
        content.insert(content.end(), response.data.begin(), response.data.end());
    };
    const auto first = read(1,chunk_units);
    append(first,chunk_units);
    if (first.amount < chunk_units) {
        return content;
    }
    const auto total = length();
    if (total < first.amount || total == (std::numeric_limits<uint64_t>::max)()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle LOB length disagrees with its first read");
    }
    uint64_t served = first.amount;
    while (served < total) {
        const auto requested = (std::min)(total-served,chunk_units);
        const auto response = read(served+1,requested);
        append(response,requested);
        if (response.amount == 0) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle LOB ended before its reported length");
        }
        served += response.amount;
    }
    return content;
}

} // namespace oracle_scanner
