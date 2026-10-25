#include "oracle_scanner/ttc_define.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_execute.hpp"
#include "oracle_scanner/ttc_row_data.hpp"

#include <algorithm>

namespace oracle_scanner {
namespace {

// DEFINE, plus the bit that makes this OALL8 a cursor call rather than a SQL one.
constexpr uint32_t DEFINE_OPTIONS = 0x8010;
// The prefetch flag python-oracledb sets on a LOB-like column's define.
constexpr uint64_t LOB_PREFETCH_FLAG = 0x02000000;
constexpr uint32_t MAX_SHORT_LENGTH = 32767;
constexpr uint32_t MAX_LONG_LENGTH = 0x7fffffff;
constexpr uint32_t DATABASE_CHARSET = 873;
// The most a response is allowed to run to, kept under TtcChannel's own bound.
constexpr size_t RESPONSE_BUDGET_BYTES = size_t {12} << 20U;
constexpr uint32_t MAXIMUM_ROWS = 128;

bool IsInlinePrefixType(uint16_t type) {
    return type == ORACLE_WIRE_TYPE_JSON || type == ORACLE_WIRE_TYPE_VECTOR;
}

// The bytes python-oracledb allots a column's value in its define. Character
// columns get four per described character, the room a UTF-8 character can
// take; the rest are the type's own width.
uint32_t DefineSize(const OracleColumn &column) {
    switch (column.oracle_type) {
    case 1:
    case 96: {
        const uint64_t size = static_cast<uint64_t>(column.byte_width) * 4U;
        return size > MAX_SHORT_LENGTH ? MAX_LONG_LENGTH : static_cast<uint32_t>(size);
    }
    case 2:
        return 22;
    case 12:
        return 7;
    case 23:
        return column.byte_width > MAX_SHORT_LENGTH ? MAX_LONG_LENGTH : column.byte_width;
    case 100:
    case 252:
        return 4;
    case 101:
        return 8;
    case 180:
    case 231:
        return 11;
    case 181:
        return 13;
    case 182:
        return 5;
    case 183:
        return 11;
    case ORACLE_WIRE_TYPE_CLOB:
    case ORACLE_WIRE_TYPE_BLOB:
        return 112;
    case ORACLE_WIRE_TYPE_JSON:
    case ORACLE_WIRE_TYPE_VECTOR:
        return INLINE_LOB_PREFIX_BYTES;
    default:
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "no define is known for Oracle type " + std::to_string(column.oracle_type));
    }
}

bool HasKnownDefine(const OracleColumn &column) {
    switch (column.oracle_type) {
    case 1:
    case 96:
    case ORACLE_WIRE_TYPE_CLOB:
        return column.character_set_form == 1 || column.character_set_form == 2;
    case 2:
    case 12:
    case 23:
    case 100:
    case 101:
    case 180:
    case 181:
    case 182:
    case 183:
    case 231:
    case 252:
    case ORACLE_WIRE_TYPE_BLOB:
    case ORACLE_WIRE_TYPE_JSON:
    case ORACLE_WIRE_TYPE_VECTOR:
        return true;
    default:
        return false;
    }
}

} // namespace

bool SupportsInlineLobDefine(const std::vector<OracleColumn> &columns, uint8_t field_version) {
    if (field_version < TTC_FIELD_VERSION_INLINE_LOBS || columns.empty() || columns.size() > 4096) {
        return false;
    }
    bool inline_column = false;
    for (const auto &column : columns) {
        if (column.omitted_from_row_data || !HasKnownDefine(column)) {
            return false;
        }
        inline_column = inline_column || IsInlinePrefixType(column.oracle_type);
    }
    return inline_column;
}

uint32_t InlineLobRows(const std::vector<OracleColumn> &columns, size_t desired) {
    size_t inline_columns = 0;
    for (const auto &column : columns) {
        inline_columns += IsInlinePrefixType(column.oracle_type) ? 1 : 0;
    }
    const size_t by_budget = (std::max)(size_t {1}, RESPONSE_BUDGET_BYTES / ((std::max)(inline_columns, size_t {1}) * INLINE_LOB_PREFIX_BYTES));
    return static_cast<uint32_t>((std::min)({desired, by_budget, size_t {MAXIMUM_ROWS}}));
}

std::vector<uint8_t> EncodeInlineLobDefine(uint8_t sequence, uint32_t cursor, const std::vector<OracleColumn> &columns,
                                           uint32_t rows) {
    if (sequence == 0 || cursor == 0 || rows == 0 || !SupportsInlineLobDefine(columns, TTC_FIELD_VERSION_INLINE_LOBS)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid inline LOB define request");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_EXECUTE).WriteByte(sequence);
    writer.WriteUB4(DEFINE_OPTIONS).WriteUB4(cursor);
    writer.WriteByte(0).WriteUB4(0).WriteByte(1).WriteUB4(13).WriteByte(0).WriteByte(0);
    writer.WriteUB4(0).WriteUB4(rows).WriteUB4(MAX_LONG_LENGTH).WriteByte(0).WriteUB4(0);
    for (unsigned i = 0; i < 5; ++i) {
        writer.WriteByte(0);
    }
    writer.WriteByte(1).WriteUB4(static_cast<uint32_t>(columns.size())).WriteUB4(0);
    writer.WriteByte(0).WriteByte(1).WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0);
    for (unsigned i = 0; i < 13; ++i) {
        writer.WriteUB4(i == 1 ? rows : i == 7 ? 1 : 0);
    }
    for (const auto &column : columns) {
        const bool lob_like = IsOracleLocatorType(column.oracle_type);
        const bool character = column.oracle_type == 1 || column.oracle_type == 96 || column.oracle_type == ORACLE_WIRE_TYPE_CLOB;
        writer.WriteByte(static_cast<uint8_t>(column.oracle_type)).WriteByte(1).WriteByte(0).WriteByte(0);
        writer.WriteUB4(DefineSize(column)).WriteUB4(0).WriteUB8(lob_like ? LOB_PREFETCH_FLAG : 0);
        writer.WriteUB4(0).WriteUB2(0).WriteUB2(character ? DATABASE_CHARSET : 0).WriteByte(character ? column.character_set_form : 0);
        writer.WriteUB4(IsInlinePrefixType(column.oracle_type) ? INLINE_LOB_PREFIX_BYTES : 0).WriteUB4(0);
    }
    return writer.Take();
}

} // namespace oracle_scanner
