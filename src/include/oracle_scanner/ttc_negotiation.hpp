#pragma once

#include "oracle_scanner/ttc_channel.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_PROTOCOL = 1;
constexpr uint8_t TTC_MESSAGE_DATA_TYPES = 2;
constexpr uint16_t ORACLE_CHARSET_AL32UTF8 = 873;
// Index of TNS_CCAP_FIELD_VERSION in a TTC capability vector, and the value
// this client advertises in its TTIDTY request. The bundled 19c template
// carries 12 at that index, and every decoder gate has to agree with what was
// actually offered rather than with a literal written at the call site.
//
// 24 is python-oracledb's TNS_CCAP_FIELD_VERSION_23_4, the highest it knows and
// the one at which a 23ai server describes a VECTOR column's dimensions and
// storage format. 17 (23_1) is the lowest at which the server sends a SQL
// BOOLEAN as its own type (252) rather than as NUMBER; 13 to 16 still get
// NUMBER. From 18 every function-call and piggyback header carries a token after
// its sequence number (TTC_FIELD_VERSION_HEADER_TOKEN) — measured on Free 23ai,
// where a client that advertised 18 without writing it got ORA-03120 — and the
// describe grows by a domain name pair (17), an annotation count (20) and the
// vector fields (24). A 19c server reports 12 and so still negotiates down to 12.
constexpr size_t TTC_CAPABILITY_FIELD_VERSION_INDEX = 7;
// Where the capability vector starts in the TTIDTY request: message type, two
// character sets, the encoding byte and the vector's length byte.
constexpr size_t TTC_DATA_TYPES_CAPABILITIES_OFFSET = 7;
constexpr uint8_t ORACLE_CLIENT_TTC_FIELD_VERSION = 24;
constexpr uint8_t TTC_FIELD_VERSION_HEADER_TOKEN = 18;

struct TtcProtocolInfo {
    uint8_t server_version = 0;
    // The lower of what this client advertised and what the server reported,
    // which is the shape both sides then speak for the request-driven parts of
    // the protocol. Live values: Oracle 19c reports 12, Free 23ai and OCI
    // Autonomous report 27, so all three negotiate to this client's 12.
    uint8_t field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    // What the server reported, before that minimum is taken. Some parts of a
    // response are shaped by this rather than by the negotiated value — the
    // end-of-call trailer is one, see TTC_FIELD_VERSION_ERROR_TRAILER.
    uint8_t server_field_version = ORACLE_CLIENT_TTC_FIELD_VERSION;
    std::string server_banner;
    uint16_t charset_id = 0;
    uint8_t server_flags = 0;
    std::vector<uint8_t> compile_capabilities;
    std::vector<uint8_t> runtime_capabilities;
};

struct TtcNegotiationOptions {
    uint8_t ttc_version = 6;
    // The bundled TTIDTY table was captured from this Thin client profile.
    // Keep TTIPRO aligned with it: Oracle uses the pair when selecting some
    // version-dependent session behavior.
    std::string driver_name = "python-oracledb";
    std::vector<uint8_t> compile_capabilities;
    std::vector<uint8_t> runtime_capabilities;
};

std::vector<uint8_t> BuildTtcProtocolRequest(const TtcNegotiationOptions &options = {});
TtcProtocolInfo ParseTtcProtocolResponse(const std::vector<uint8_t> &message);
std::vector<uint8_t> BuildTtcDataTypesRequest(const TtcNegotiationOptions &options = {});
void ValidateTtcDataTypesResponse(const std::vector<uint8_t> &message);
TtcProtocolInfo RunTtcNegotiation(TtcChannel &channel, const TtcNegotiationOptions &options = {});

} // namespace oracle_scanner
