#include "oracle_scanner/ttc_ano_negotiation.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

namespace {

// The capability advertisement captured from a JDBC client talking to a live
// Oracle 11.2 listener. The four magic bytes and the two length bytes that
// BuildLegacyAnoRequest writes in front of it are not part of it.
constexpr std::array<uint8_t, 134> LEGACY_ANO_CAPABILITIES = {
    0x17, 0x70, 0x19, 0x01, 0x00, 0x04, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x17, 0x70, 0x19, 0x01, 0x00,
    0x08, 0x00, 0x01, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x00,
    0x12, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x01, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x05, 0x17, 0x70, 0x19,
    0x01, 0x00, 0x02, 0x00, 0x03, 0xe0, 0xe1, 0x00, 0x02, 0x00, 0x06, 0xfc,
    0xff, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x05, 0x17, 0x70, 0x19, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x0f, 0x10,
    0x11, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x05, 0x17, 0x70, 0x19, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03, 0x04,
    0x05, 0x06,
};

constexpr uint8_t LEGACY_ANO_MAGIC[4] = {0xde, 0xad, 0xbe, 0xef};

} // namespace

std::vector<uint8_t> BuildLegacyAnoRequest() {
    ByteWriter writer;
    writer.WriteRaw(LEGACY_ANO_MAGIC, sizeof(LEGACY_ANO_MAGIC));
    // The length counts the magic, this field and the capability table: the
    // listener reads it as "how long is this message", counted from the
    // magic. A listener that gets a different number here answers nothing.
    writer.WriteUInt16BE(static_cast<uint16_t>(6 + LEGACY_ANO_CAPABILITIES.size()));
    writer.WriteRaw(LEGACY_ANO_CAPABILITIES.begin(), LEGACY_ANO_CAPABILITIES.size());
    return writer.Take();
}

void ValidateLegacyAnoResponse(const std::vector<uint8_t> &message) {
    if (message.size() < 6) {
        throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle ANO answer is too short");
    }
    for (size_t index = 0; index < sizeof(LEGACY_ANO_MAGIC); index++) {
        if (message[index] != LEGACY_ANO_MAGIC[index]) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                "Oracle ANO answer does not start with the expected magic");
        }
    }
    const auto declared = static_cast<uint16_t>((static_cast<uint16_t>(message[4]) << 8U) |
                                                 static_cast<uint16_t>(message[5]));
    if (static_cast<size_t>(declared) != message.size()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "Oracle ANO answer has an inconsistent length");
    }
}

void RunLegacyAnoNegotiation(TtcChannel &channel) {
    channel.Send(BuildLegacyAnoRequest());
    ValidateLegacyAnoResponse(channel.Receive());
}

} // namespace oracle_scanner
