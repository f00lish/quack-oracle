#pragma once

#include "oracle_scanner/ttc_channel.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

// The TNS version at and below which a listener speaks the legacy session
// dialect. 11.2 answers 314; 12.1 and later answer 317 and up, and 19c
// answers 318 or 319.
//
// Two things change with it, and both are keyed off this one value:
//   - the packet header length form (two bytes against a legacy listener,
//     four against a modern one),
//   - the Additional Network Option negotiation below, which a legacy
//     listener expects and a modern one does not.
constexpr uint16_t LEGACY_SESSION_MAX_TNS_VERSION = 314;

// Oracle's "Additional Network Option" (ANO) negotiation.
//
// On the legacy dialect the listener expects one more round trip between
// ACCEPT and the TTC protocol negotiation: the client states which session
// services it supports — authentication, encryption, data integrity — and
// the listener answers with the ones it will use. A client that skips it is
// not answered at all, which is what made 11.2 look like a server that had
// gone silent.
//
// The request is a fixed capability advertisement. It was captured from a
// JDBC client talking to a live 11.2 listener and then verified against
// that listener byte by byte: corrupting the magic, the framing items or
// the capability table makes the listener stop answering, while the client
// platform id and the trailing service versions can be changed without
// breaking the exchange. The captured values are kept because they are what
// a real client sends — in particular the service versions decline native
// network encryption, which is true of this client as well.
std::vector<uint8_t> BuildLegacyAnoRequest();

// Checks the listener's answer. The answer carries the service versions the
// two sides agreed on, but this client needs none of them: it speaks O5LOGON
// and no native network encryption, and the TTC negotiation that follows
// reports everything the session actually uses.
void ValidateLegacyAnoResponse(const std::vector<uint8_t> &message);

// Runs the exchange. The channel must still be at the transport level: this
// is the first thing a legacy session sends after ACCEPT.
void RunLegacyAnoNegotiation(TtcChannel &channel);

} // namespace oracle_scanner
