#pragma once

#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/byte_buffer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_PARAMETER = 8;

struct TtcParameter {
    std::string key;
    std::string value;
    uint32_t flags = 0;
};

struct TtcReturnParameterPrefix {
    size_t bytes_consumed = 0;
};

std::vector<uint8_t> EncodeTtcParameters(const std::vector<TtcParameter> &parameters);
// `chunk_encoding` says how the session states the length of each piece of a
// long value: a universal integer on 19c and later, one raw byte on 11.2.
std::vector<TtcParameter> DecodeTtcParameters(const std::vector<uint8_t> &message,
                                               TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);
// Drains the execute-response RETURN_PARAMETER body (message type 8). It is
// distinct from the authentication key/value PARAMETER grammar above.
TtcReturnParameterPrefix DecodeTtcReturnParameterPrefix(const std::vector<uint8_t> &message);
O5LogonChallenge O5LogonChallengeFromParameters(const std::vector<TtcParameter> &parameters);
// Reads an 11G challenge. An 11G challenge has a different parameter set from
// 12C: it carries no PBKDF2 iteration counts and no combo-key salt.
//
// `padded` is the server's answer to "are the session keys padded?", which
// comes from the capability table rather than from the challenge itself:
// (ServerCompileTimeCaps[4] & 2) == 0.
O5Logon11GChallenge O5Logon11GChallengeFromParameters(const std::vector<TtcParameter> &parameters, bool padded);

} // namespace oracle_scanner
