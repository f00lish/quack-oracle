#include "oracle_scanner/ttc_o5logon.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_error.hpp"

#include <map>

namespace oracle_scanner {

O5LogonResponse RunO5Logon(TtcChannel &channel, const O5LogonRequest &request) {
    if (request.username.empty() || request.username.size() > 252 || request.password.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON request is incomplete");
    }
    // The 12C path needs three random values of exact sizes; the 11G path
    // makes its own session key and has no speedy key. A wrong size is not
    // fatal on its own -- which verifier it is only becomes known once the
    // challenge arrives -- so the values are padded to the size the 12C path
    // needs and the 12C path checks them again when it uses them.
    O5LogonRequest local = request;
    if (local.client_session_key.size() != 32) {
        local.client_session_key.resize(32, 0);
    }
    if (local.password_salt.size() != 16) {
        local.password_salt.resize(16, 0);
    }
    if (local.speedy_key_salt.size() != 16) {
        local.speedy_key_salt.resize(16, 0);
    }
    // A legacy listener states the length of each piece of a long value as one
    // raw byte; a modern one states it as a universal integer. Which one it
    // is comes from the session's own legacy marker, not from a bit of the
    // capability table: the 19c capability table has caps[37] == 0x01, so the
    // test go-ora uses to decide this would treat 19c as legacy.
    const auto chunk_encoding = ChunkEncodingFor(local.legacy_session);
    channel.Send(EncodeTtcAuthFunction(TTC_FUNCTION_AUTH_PHASE_ONE, 1, local.username, local.auth_mode,
                                       local.phase_one_parameters, chunk_encoding));
    auto challenge_response = channel.Receive();
    if (IsTtcErrorMessage(challenge_response)) {
        ThrowTtcServerError(challenge_response);
    }
    auto challenge_parameters = DecodeTtcParameters(challenge_response, chunk_encoding);
    // The verifier in the challenge decides the algorithm. Reading it first
    // keeps a 12C challenge from being answered with the 11G one, and the
    // other way round.
    uint32_t verifier_type = 0;
    for (const auto &parameter : challenge_parameters) {
        if (parameter.key == "AUTH_VFR_DATA") {
            verifier_type = parameter.flags;
        }
    }
    O5LogonResponse response;
    if (verifier_type == O5LOGON_VERIFIER_11G_1 || verifier_type == O5LOGON_VERIFIER_11G_2) {
        auto challenge = O5Logon11GChallengeFromParameters(challenge_parameters, local.session_keys_padded);
        response = BuildO5Logon11GResponse(local.password, challenge);
    } else {
        auto challenge = O5LogonChallengeFromParameters(challenge_parameters);
        response = BuildO5LogonResponse(local.password, challenge, local.client_session_key, local.password_salt,
                                         local.speedy_key_salt);
    }
    auto phase_two_parameters = BuildO5LogonPhaseTwoParameters(response);
    // This order matches the direct successful Thin capture: key material and
    // password proof precede session metadata.
    phase_two_parameters.insert(phase_two_parameters.end(), local.phase_two_parameters.begin(),
                                local.phase_two_parameters.end());
    channel.Send(EncodeTtcAuthFunction(TTC_FUNCTION_AUTH_PHASE_TWO, 2, local.username, 0x0101,
                                       phase_two_parameters, chunk_encoding));

    auto proof_response = channel.Receive();
    if (IsTtcErrorMessage(proof_response)) {
        ThrowTtcServerError(proof_response);
    }
    std::map<std::string, std::string> values;
    for (const auto &parameter : DecodeTtcParameters(proof_response, chunk_encoding)) {
        if (!values.emplace(parameter.key, parameter.value).second) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "O5LOGON phase-two response has duplicate parameters");
        }
    }
    const auto proof = values.find("AUTH_SVR_RESPONSE");
    if (proof == values.end() || !VerifyO5LogonServerResponse(response, proof->second)) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "Oracle O5LOGON server proof is invalid");
    }
    return response;
}

} // namespace oracle_scanner
