#pragma once

#include "lob_prefetch_reader.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/ttc_negotiation.hpp"

namespace oracle_scanner {

// Isolated single-column probe, not a generic query/define implementation.
// Layout verified against ordinary JDBC 19.3 post-auth SELECT captures on
// owned 19c and Free servers. No SQL is resent by the define operation.
//
// `chunk_encoding` says how the session states the length of a long value: a
// universal integer on 19c and later, one raw byte on 11.2.
inline std::vector<uint8_t> EncodeLobPrefetchProbeRequest(uint8_t sequence, uint32_t cursor,
                                                        const std::string &sql, uint16_t type,
                                                        uint8_t form, uint32_t prefix_units,
                                                        uint8_t field_version,
                                                        TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger) {
    const bool define = cursor != 0;
    if (sequence == 0 || field_version != 12 || prefix_units > 32768 ||
        (type != 112 && type != 113) || (form != 1 && form != 2) ||
        (define ? !sql.empty() : sql.empty() || sql.size() > (1U << 20U) || sql.find('\0') != std::string::npos)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid isolated LOB prefetch probe request");
    }
    ByteWriter writer;
    writer.WriteByte(3).WriteByte(94).WriteByte(sequence);
    writer.WriteUB4(define ? 0x8050 : 0x8021).WriteUB4(cursor);
    writer.WriteByte(define ? 0 : 1).WriteUB4(static_cast<uint32_t>(sql.size()));
    writer.WriteByte(1).WriteUB4(13).WriteByte(0).WriteByte(0);
    writer.WriteUB4(0).WriteUB4(define ? 0 : 1).WriteUB4(0x7fffffff);
    writer.WriteByte(0).WriteUB4(0);
    for (unsigned i = 0; i < 5; ++i) { writer.WriteByte(0); }
    writer.WriteByte(define ? 1 : 0).WriteUB4(define ? 1 : 0).WriteUB4(0);
    writer.WriteByte(0).WriteByte(1).WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteUB4(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0).WriteByte(0).WriteUB4(0).WriteByte(0);
    writer.WriteByte(0).WriteUB4(0); // field-version 12 extension
    if (!define) {
        writer.WriteLengthPrefixed(std::vector<uint8_t>(sql.begin(), sql.end()), chunk_encoding);
    }
    for (unsigned i = 0; i < 13; ++i) {
        writer.WriteUB4(i == 0 ? (define ? 0 : 1) : i == 1 ? (define ? 1 : 0) :
                        i == 7 ? 1 : i == 9 && !define ? 0x8000 : 0);
    }
    if (define) {
        writer.WriteByte(static_cast<uint8_t>(type)).WriteByte(3).WriteByte(0).WriteByte(0);
        writer.WriteUB4(0).WriteUB4(0).WriteUB8(0x02000000).WriteUB4(0).WriteUB2(0);
        writer.WriteUB2(form == 2 ? 2000 : 873).WriteByte(form).WriteUB4(prefix_units).WriteUB4(0);
    }
    return writer.Take();
}

inline std::optional<OracleLobPrefetch> DecodeLobPrefetchProbeCell(ByteReader &reader, bool character,
                                                                 uint32_t requested_units,
                                                                 size_t content_budget,
                                                                 TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger,
                                                                 uint16_t national_charset = 0) {
    if (requested_units > 32768 || content_budget == 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid LOB prefetch decoder bounds");
    }
    const auto locator_size = reader.ReadUB4();
    if (locator_size == 0) { return std::nullopt; }
    if (locator_size > 4096) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "LOB prefetch locator exceeds bounds");
    }
    OracleLobPrefetch result;
    result.character = character;
    result.total_units = reader.ReadUB8();
    const auto width = character ? 2U : 1U;
    if (result.total_units > content_budget / width) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "LOB prefetch length exceeds content budget");
    }
    reader.ReadUB4(); // chunk size is metadata, not an allocation request
    if (requested_units != 0) {
        if (character) {
            const auto has_charset = reader.ReadByte();
            if (has_charset > 1) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid LOB prefetch charset flag");
            }
            const auto charset = has_charset ? reader.ReadUB2() : national_charset;
            const auto form = reader.ReadByte();
            if (charset != 2000 || (form != 1 && form != 2) || (!has_charset && form != 2)) {
                throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "LOB prefetch charset is not verified UTF-16BE");
            }
        }
        auto prefix = reader.ReadLengthPrefixed(static_cast<size_t>(requested_units) * width, chunk_encoding);
        if (prefix) { result.prefix = std::move(*prefix); }
        if (result.prefix.size() % width != 0) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch has an incomplete UTF-16 unit");
        }
        result.prefix_units = result.prefix.size() / width;
        if (result.prefix_units > result.total_units) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch exceeds its reported length");
        }
    }
    auto locator = reader.ReadLengthPrefixed(locator_size, chunk_encoding);
    if (!locator || locator->size() != locator_size) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "LOB prefetch locator length mismatch");
    }
    result.locator = std::move(*locator);
    return result;
}

} // namespace oracle_scanner
