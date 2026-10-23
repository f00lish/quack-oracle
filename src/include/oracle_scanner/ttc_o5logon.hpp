#pragma once

#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_channel.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

struct O5LogonRequest {
    std::string username;
    std::string password;
    uint32_t auth_mode = 0;
    std::vector<TtcParameter> phase_one_parameters;
    std::vector<TtcParameter> phase_two_parameters;
    std::vector<uint8_t> client_session_key;
    std::vector<uint8_t> password_salt;
    std::vector<uint8_t> speedy_key_salt;
    // Whether the 11G server's session keys are padded. It comes from the
    // capability table: (ServerCompileTimeCaps[4] & 2) == 0 means padded.
    // 12C ignores it.
    bool session_keys_padded = true;
    // Whether the listener speaks the legacy session dialect. It answers with
    // a two-byte packet length and states the length of each piece of a long
    // value as one raw byte instead of a universal integer.
    //
    // This is the extension's own legacy marker (accept_version <= 314), not
    // a bit of the capability table: the 19c capability table has
    // caps[37] == 0x01, so the bit go-ora uses to decide this is not set
    // there, and copying that test would break the 19c path.
    bool legacy_session = false;
};

// Performs the TTC parameter exchange for the 12c verifier. The caller must
// run TNS and TTC negotiation first and provide fresh 32/16-byte randomness.
O5LogonResponse RunO5Logon(TtcChannel &channel, const O5LogonRequest &request);

} // namespace oracle_scanner
