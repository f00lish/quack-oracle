#pragma once

#include "oracle_scanner/byte_buffer.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_ROW_DATA = 7;

// Decodes one scalar TTC ROW_DATA frame after a describe response has fixed
// the column count. Type conversion is intentionally left to value_codec.
using TtcRowData = std::vector<std::optional<std::vector<uint8_t>>>;
struct TtcRowDataPrefix {
    TtcRowData values;
    size_t bytes_consumed = 0;
};

// A LOB column does not send its value. It sends a locator, and it frames that
// locator differently from every other value: a universal-integer length
// instead of the single length byte a scalar uses, and one trailing byte after
// it. Reading it as a scalar consumes the length's own first byte as the value
// and then treats the next byte as a message type, which is how this announced
// itself — "unknown TTC message 114", 114 being the locator's length.
// Captured from 19c for CLOB and BLOB alike; a NULL LOB is a single zero, the
// same as any other NULL.
constexpr uint16_t ORACLE_WIRE_TYPE_CLOB = 112;
constexpr uint16_t ORACLE_WIRE_TYPE_BLOB = 113;

inline bool IsOracleLobType(uint16_t oracle_type) {
    return oracle_type == ORACLE_WIRE_TYPE_CLOB || oracle_type == ORACLE_WIRE_TYPE_BLOB;
}

// A value longer than 252 bytes is framed as a `0xFE` marker followed by
// chunk lengths. The chunk length is stated in the session's own dialect: a
// universal integer on a modern session, a single raw byte on a legacy (11.2)
// one. Reading a legacy chunk length as a universal integer consumes the
// length byte as a width and then the value's own bytes as the number, so
// the row desynchronizes and the value never decodes.
//
// The encoding is therefore the caller's to state, from the session's own
// legacy marker, exactly as the database-version response does.
TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, const std::vector<bool> &is_lob,
                                        size_t maximum_value_bytes = (1U << 20U),
                                        TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);
// The same, reading from a position inside a larger response rather than from
// a copy of what is left of it.
TtcRowDataPrefix DecodeTtcRowDataPrefix(const uint8_t *data, size_t size, const std::vector<bool> &is_lob,
                                        size_t maximum_value_bytes = (1U << 20U),
                                        TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);

TtcRowDataPrefix DecodeTtcRowDataPrefix(const std::vector<uint8_t> &message, size_t column_count,
                                        size_t maximum_value_bytes = 16U << 20U,
                                        TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);
TtcRowData DecodeTtcRowData(const std::vector<uint8_t> &message, size_t column_count,
                            size_t maximum_value_bytes = 16U << 20U,
                            TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);

} // namespace oracle_scanner
