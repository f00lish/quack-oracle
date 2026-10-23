#include "oracle_scanner/tns_connect.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <limits>

namespace oracle_scanner {

namespace {

constexpr size_t CONNECT_FIXED_PAYLOAD_SIZE = 66;
constexpr size_t CONNECT_HEADER_TOTAL_SIZE = TNS_PACKET_HEADER_SIZE + CONNECT_FIXED_PAYLOAD_SIZE;
// Every official Oracle client puts the whole connect descriptor inside the
// CONNECT packet: ojdbc8 sends 202 bytes inline for a short service name,
// and sends a longer descriptor inline as well. 230 was a guess at that
// limit, and it was wrong in the direction that breaks. Past it the
// descriptor moves to a DATA continuation -- and an 11.2 listener never
// reads the descriptor from there: it accepts the session and then stops
// answering, while the very same request sent inline gets a reply. 2048 is
// the practical inline ceiling; a descriptor past that still uses the
// continuation, and that case is not supported against 11.2.
constexpr size_t MAX_INLINE_CONNECT_DATA = 2048;

void StoreUInt16(std::vector<uint8_t> &target, size_t offset, uint16_t value) {
    target[offset] = static_cast<uint8_t>(value >> 8U);
    target[offset + 1] = static_cast<uint8_t>(value);
}

void StoreUInt32(std::vector<uint8_t> &target, size_t offset, uint32_t value) {
    target[offset] = static_cast<uint8_t>(value >> 24U);
    target[offset + 1] = static_cast<uint8_t>(value >> 16U);
    target[offset + 2] = static_cast<uint8_t>(value >> 8U);
    target[offset + 3] = static_cast<uint8_t>(value);
}

} // namespace

std::vector<TnsPacket> BuildTnsConnectPackets(const std::string &descriptor, const TnsConnectOptions &options) {
    if (descriptor.empty() || descriptor.size() > (std::numeric_limits<uint16_t>::max)() - TNS_PACKET_HEADER_SIZE - 2 ||
        options.desired_version < options.minimum_version || options.requested_sdu < 512 ||
        options.requested_tdu < options.requested_sdu) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "TNS CONNECT parameters are invalid");
    }
    const auto descriptor_is_inline = descriptor.size() <= MAX_INLINE_CONNECT_DATA;
    std::vector<uint8_t> payload(CONNECT_FIXED_PAYLOAD_SIZE + (descriptor_is_inline ? descriptor.size() : 0), 0);
    StoreUInt16(payload, 0, options.desired_version);
    StoreUInt16(payload, 2, options.minimum_version);
    // The service options, the connect flags and the two 32-bit data units
    // below are ojdbc8's, byte for byte, because a CONNECT that carries them
    // is the one an 11.2 listener answers. The same CONNECT with the
    // extension's own values -- service options 0x0401, transmission data
    // unit 8192, connect flags 0x8484 -- gets an ACCEPT and then silence on
    // the very next request. ojdbc8 8.2.0 sent these to this very database,
    // and go-ora sends the same urgent-data bit (0x0400) with 0x0801.
    StoreUInt16(payload, 4, static_cast<uint16_t>(0x0841 | (options.supports_oob ? 0x0400 : 0)));
    StoreUInt16(payload, 6, options.requested_sdu);
    StoreUInt16(payload, 8, options.requested_tdu); // transmission data unit
    StoreUInt16(payload, 10, 0x4f98); // current thin-client protocol characteristics
    StoreUInt16(payload, 14, 0x0001); // connect value
    StoreUInt16(payload, 16, static_cast<uint16_t>(descriptor.size()));
    StoreUInt16(payload, 18, static_cast<uint16_t>(CONNECT_HEADER_TOTAL_SIZE));
    StoreUInt32(payload, 20, 0); // no extra receive buffer reservation
    payload[24] = 0x81;
    payload[25] = 0x81; // connect flags, as ojdbc8 sends them
    payload[52] = 0x20; // session data unit, 8192
    payload[55] = 0x20; // transmission data unit, 2 MB -- one byte lower than before,
                        // which had put 0x20 in the wrong field and asked for 512 MB
    payload[65] = options.supports_oob ? 0x01 : 0x00;
    if (descriptor_is_inline) {
        std::copy(descriptor.begin(), descriptor.end(), payload.begin() + CONNECT_FIXED_PAYLOAD_SIZE);
    }
    std::vector<TnsPacket> packets;
    packets.push_back({TnsPacketType::CONNECT, options.packet_flags, std::move(payload)});
    if (!descriptor_is_inline) {
        // The client must not duplicate long connect data: the listener reads
        // it from the DATA continuation before it sends ACCEPT.
        std::vector<uint8_t> continuation(2 + descriptor.size());
        std::copy(descriptor.begin(), descriptor.end(), continuation.begin() + 2);
        packets.push_back({TnsPacketType::DATA, 0, std::move(continuation)});
    }
    return packets;
}

} // namespace oracle_scanner
