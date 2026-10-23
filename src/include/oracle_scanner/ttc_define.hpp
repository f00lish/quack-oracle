#pragma once

#include "oracle_scanner/session.hpp"

#include <cstdint>
#include <vector>

namespace oracle_scanner {

// A query over JSON or VECTOR columns hands back a locator for each value,
// and reading the value is then a round trip of its own — or two. Both types
// can instead arrive with the row: after the describe, the client re-executes
// the same cursor with a define for every column, and for these two says how
// many bytes of the value to send ahead of the locator. This is the exchange
// python-oracledb Thin makes, byte for byte (see PROVENANCE.md).
//
// A value longer than the bytes asked for arrives cut short with its locator,
// and the rest is read from that locator.
constexpr uint8_t TTC_FIELD_VERSION_INLINE_LOBS = 17;
constexpr uint32_t INLINE_LOB_PREFIX_BYTES = 64U * 1024U;

// Whether the define can be written for these columns: the server speaks
// JSON (field version 17 and up), a column is JSON or VECTOR, and every
// column is a type whose define is known. ROWID, LONG and the like are not,
// and a column the server leaves out of ROW_DATA cannot be defined.
bool SupportsInlineLobDefine(const std::vector<OracleColumn> &columns, uint8_t field_version);

// How many rows to ask for so that, whatever the values, the response stays
// inside the channel's message bound.
uint32_t InlineLobRows(const std::vector<OracleColumn> &columns, size_t desired);

// The define-and-fetch request, without the token a field-version-18 header
// carries (the channel adds it). `rows` is how many rows the response may hold.
std::vector<uint8_t> EncodeInlineLobDefine(uint8_t sequence, uint32_t cursor, const std::vector<OracleColumn> &columns,
                                           uint32_t rows);

} // namespace oracle_scanner
