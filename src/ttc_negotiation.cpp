#include "oracle_scanner/ttc_negotiation.hpp"

#include <algorithm>
#include "oracle_scanner/ttc_data_types_template.hpp"
#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_error.hpp"

#include <algorithm>

namespace oracle_scanner {

namespace {

// A capability vector's length is a plain byte, so it cannot exceed 255.
constexpr size_t MAX_CAPABILITY_VECTOR_BYTES = 255;
// The data-types response carries the capability vectors and the whole type
// representation table, so it is bounded on its own and much more loosely.
constexpr size_t MAX_CAPABILITY_BYTES = 4096;
constexpr size_t MAX_BANNER_BYTES = 1024;

// The capability vectors in the TTC protocol and data-types messages are not
// long values. Their length is a plain single byte, and go-ora reads it as
// one: network/session.go GetByte() then GetBytes(len), with no 0xFE marker
// and no chunk encoding anywhere in it (tcp_protocol_nego.go reads the
// server's vectors that way, data_type_nego.go writes the client's that way).
// The session's chunk encoding therefore does not apply to them, and a
// length-prefixed read would be wrong twice over: it would refuse a vector
// whose length byte is 0xFE or 0xFF, and it would read a longer one as a
// chunked value. A capability vector is a fixed table of flags, so a plain
// byte is all it needs.
std::vector<uint8_t> ReadCapabilities(ByteReader &reader) {
    const auto length = reader.ReadByte();
    if (length == 0) {
        return {};
    }
    return reader.ReadRaw(length);
}

void WriteCapabilities(ByteWriter &writer, const std::vector<uint8_t> &value) {
    if (value.size() > MAX_CAPABILITY_VECTOR_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC capability vector is too large");
    }
    writer.WriteByte(static_cast<uint8_t>(value.size()));
    writer.WriteRaw(value);
}

bool LooksLikeAno(const std::vector<uint8_t> &message) {
    return message.size() >= 4 && message[0] == 0xde && message[1] == 0xad && message[2] == 0xbe &&
           message[3] == 0xef;
}

} // namespace

std::vector<uint8_t> BuildTtcProtocolRequest(const TtcNegotiationOptions &options) {
    if ((options.ttc_version != 6 && options.ttc_version != 8) || options.driver_name.empty() ||
        options.driver_name.size() > MAX_BANNER_BYTES ||
        options.driver_name.find('\0') != std::string::npos) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC protocol request options are invalid");
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_PROTOCOL).WriteByte(options.ttc_version).WriteByte(0);
    writer.WriteNullTerminated(options.driver_name);
    return writer.Take();
}

TtcProtocolInfo ParseTtcProtocolResponse(const std::vector<uint8_t> &message) {
    if (LooksLikeAno(message)) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle Native Network Encryption is not supported");
    }
    ByteReader reader(message);
    if (reader.ReadByte() != TTC_MESSAGE_PROTOCOL) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC protocol response");
    }
    TtcProtocolInfo result;
    result.server_version = reader.ReadByte();
    reader.Skip(1); // reserved byte
    result.server_banner = reader.ReadNullTerminated(MAX_BANNER_BYTES);
    result.charset_id = reader.ReadUInt16LE();
    result.server_flags = reader.ReadByte();
    const auto element_count = reader.ReadUInt16LE();
    if (element_count > 512) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC protocol element table is too large");
    }
    reader.Skip(static_cast<size_t>(element_count) * 5);
    const auto fdo_size = reader.ReadUInt16BE();
    if (fdo_size > MAX_CAPABILITY_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC format descriptor is too large");
    }
    reader.Skip(fdo_size);
    result.compile_capabilities = ReadCapabilities(reader);
    if (result.compile_capabilities.size() > TTC_CAPABILITY_FIELD_VERSION_INDEX) {
        result.server_field_version = result.compile_capabilities[TTC_CAPABILITY_FIELD_VERSION_INDEX];
        result.field_version = (std::min)(ORACLE_CLIENT_TTC_FIELD_VERSION, result.server_field_version);
    }
    result.runtime_capabilities = ReadCapabilities(reader);
    // Newer servers can append a small, versioned trailer. Its contents are
    // not consumed until a live compatibility matrix has been established.
    if (reader.Remaining() > 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TTC protocol response has an unknown oversized trailer");
    }
    return result;
}

std::vector<uint8_t> BuildTtcDataTypesRequest(const TtcNegotiationOptions &options) {
    if (options.compile_capabilities.empty() && options.runtime_capabilities.empty()) {
        return {ORACLE_19C_TTC_DATA_TYPES_TEMPLATE.begin(), ORACLE_19C_TTC_DATA_TYPES_TEMPLATE.end()};
    }
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_DATA_TYPES).WriteUInt16LE(ORACLE_CHARSET_AL32UTF8).WriteUInt16LE(ORACLE_CHARSET_AL32UTF8);
    writer.WriteByte(0); // standard encoding representation
    WriteCapabilities(writer, options.compile_capabilities);
    WriteCapabilities(writer, options.runtime_capabilities);
    writer.WriteUInt16BE(0); // no client type-representation overrides
    return writer.Take();
}

void ValidateTtcDataTypesResponse(const std::vector<uint8_t> &message) {
    if (LooksLikeAno(message)) {
        throw ProtocolError(ProtocolErrorKind::UNSUPPORTED, "Oracle Native Network Encryption is not supported");
    }
    if (message.empty() || message[0] != TTC_MESSAGE_DATA_TYPES) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected TTC data-types response");
    }
    if (message.size() > MAX_CAPABILITY_BYTES * 4) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "TTC data-types response is too large");
    }
}

TtcProtocolInfo RunTtcNegotiation(TtcChannel &channel, const TtcNegotiationOptions &options) {
    channel.Send(BuildTtcProtocolRequest(options));
    auto protocol_response = channel.Receive();
    if (IsTtcErrorMessage(protocol_response)) {
        ThrowTtcServerError(protocol_response);
    }
    auto protocol = ParseTtcProtocolResponse(protocol_response);
    // The server reports its own character set here; it is not a negotiation.
    // This client asks for AL32UTF8 in TTIDTY and Oracle converts on the server
    // side, so a database in any character set is readable — refusing anything
    // but AL32UTF8 turned "your database is not UTF-8" into "unsupported", which
    // is neither true nor actionable.
    channel.Send(BuildTtcDataTypesRequest(options));
    auto data_types_response = channel.Receive();
    if (IsTtcErrorMessage(data_types_response)) {
        ThrowTtcServerError(data_types_response);
    }
    ValidateTtcDataTypesResponse(data_types_response);
    return protocol;
}

} // namespace oracle_scanner
