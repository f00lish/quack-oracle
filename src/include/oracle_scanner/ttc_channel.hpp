#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/data_assembler.hpp"
#include "oracle_scanner/ttc_dialect.hpp"
#include "oracle_scanner/ttc_piggyback.hpp"
#include "oracle_scanner/ttc_transaction.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace oracle_scanner {

// TNS DATA packetisation for one bidirectional TTC message stream. Calls are
// synchronous by design: Oracle TTC has one active request per session.
class TtcChannel {
public:
    TtcChannel(TnsPacketStream &packets, size_t negotiated_sdu, size_t maximum_message_size = 16U << 20U,
               bool cancellation_supported = true, TtcDialect dialect = TtcDialect{});

    // Queues a server cursor release for the next TTC function call. Oracle
    // defines CLOSE_CURSORS as a piggyback, so sending it independently would
    // leave the session waiting for a function body that never arrives.
    void QueueCloseCursor(uint32_t cursor_id);
    size_t PendingCloseCursorCount() const;
    // Queues the session's end-to-end attributes (module, action, ...) for the
    // next function call, where they travel as a piggyback.
    void QueueEndToEndAttributes(const TtcEndToEndAttributes &attributes);
    // A round trip that does nothing but carry what is queued (the end-to-end
    // attributes) and hear the server acknowledge it.
    void Ping(uint8_t sequence, uint8_t server_field_version = 12);
    TtcTransactionStatus Commit(uint8_t sequence, uint8_t server_field_version = 12);
    TtcTransactionStatus Rollback(uint8_t sequence, uint8_t server_field_version = 12);
    // Sends the capture-verified TCP interrupt marker. The reader that owns
    // the in-flight response completes the subsequent RESET exchange.
    void Cancel();
    // The negotiated TTC field version, which decides the shape of every request header.
    void SetWireFieldVersion(uint8_t field_version) { wire_field_version = field_version; }
    void Send(const std::vector<uint8_t> &message);
    std::vector<uint8_t> Receive();

    // Whether the listener speaks the legacy (11.2) session dialect. The
    // dialect decides the layout of several TTC bodies -- the TTIOER error
    // body above all -- so a decoder that does not know it decodes a legacy
    // message with the modern layout and reports a width error instead of
    // the server's own message.
    bool LegacySession() const {
        return dialect.chunk_encoding == TtcChunkEncoding::RawByte;
    }

    // The session's dialect. It is ONE value rather than a flag plus a
    // separate encoding argument, so a function that has to know how the
    // session states a length takes the dialect and not a pair of loose
    // parameters that could disagree with each other.
    const TtcDialect &Dialect() const {
        return dialect;
    }

    // One TTC call is a request and the response that answers it, and the two
    // are only a pair because nothing else uses the channel in between. A
    // session shared by two DuckDB pipelines has no such guarantee, so every
    // caller that sends and then reads holds this for both halves. It is
    // deliberately not taken by Cancel: an interrupt exists to reach a call
    // that is already blocked on its own response.
    std::unique_lock<std::recursive_mutex> LockCall() {
        return std::unique_lock<std::recursive_mutex>(call_mutex);
    }

private:
    TtcTransactionStatus ReceiveTransactionStatus(uint8_t server_field_version);
    TnsPacketStream &packets;
    size_t negotiated_sdu;
    TnsDataAssembler assembler;
    std::vector<uint32_t> pending_close_cursors;
    TtcEndToEndAttributes pending_end_to_end;
    uint8_t next_piggyback_sequence = 1;
    uint8_t wire_field_version = 0;
    bool cancellation_supported;
    TtcDialect dialect;
    std::atomic<bool> cancellation_requested {false};
    std::mutex outbound_mutex;
    std::recursive_mutex call_mutex;
};

} // namespace oracle_scanner
