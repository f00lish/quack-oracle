#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace oracle_scanner {

// Returns bytes from OpenSSL's operating-system-backed CSPRNG. This is used
// for ephemeral authentication material and must never be replaced with a
// deterministic generator.
std::vector<uint8_t> SecureRandomBytes(size_t size);
std::string Base64Encode(const std::vector<uint8_t> &value);
std::vector<uint8_t> Pbkdf2Sha512(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt,
                                  uint32_t iterations, size_t output_size);
std::vector<uint8_t> Sha512(const std::vector<std::vector<uint8_t>> &parts);
// SHA-1 and MD5 exist for the 11G password verifier only: 11G derives its key
// with SHA-1 and its combo key with MD5, while 12C is PBKDF2-SHA-512.
std::vector<uint8_t> Sha1(const std::vector<uint8_t> &value);
std::vector<uint8_t> Md5(const std::vector<uint8_t> &value);
std::vector<uint8_t> AesCbcEncrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext);
std::vector<uint8_t> AesCbcDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
std::vector<uint8_t> AesCbcEncryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext);
std::vector<uint8_t> AesCbcDecryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
std::string UpperHex(const std::vector<uint8_t> &value);
std::vector<uint8_t> DecodeHex(const std::string &value, size_t maximum_bytes);

// The password verifier a challenge is built on, from the flags of its
// AUTH_VFR_DATA parameter. 12C and 11G are supported. The others are named so
// an unsupported account is reported as what it is, not as a malformed message;
// the values are the ones python-oracledb Thin's constants.pxi lists.
constexpr uint32_t O5LOGON_VERIFIER_12C = 0x4815;
constexpr uint32_t O5LOGON_VERIFIER_11G_1 = 0xB152;
constexpr uint32_t O5LOGON_VERIFIER_11G_2 = 0x1B25;
constexpr uint32_t O5LOGON_VERIFIER_10G = 0x0939;

// Throws UNSUPPORTED, naming the verifier by type, unless it is 12C or 11G.
void RequireSupportedO5LogonVerifier(uint32_t verifier_type);

// Throws UNSUPPORTED unless the verifier is 12C.
//
// The stricter question, asked by the 12C paths: RequireSupportedO5LogonVerifier
// answers "does this client implement the verifier the server offered", and
// it allows 11G now. The 12C algorithm and the 11G algorithm derive their
// keys completely differently, so a 12C path that accepts an 11G challenge
// would build a well-formed response with the wrong keys in it.
void Require12CVerifier(uint32_t verifier_type);

struct O5LogonChallenge {
    std::string verifier_data_hex;
    std::string server_session_key_hex;
    std::string combo_key_salt_hex;
    uint32_t verifier_iterations = 0;
    uint32_t combo_key_iterations = 0;
    uint32_t verifier_type = 0;
};

// An 11G challenge. It has a different shape from 12C: no PBKDF2 iteration
// counts, no combo-key salt, and the session keys are 48 bytes of ciphertext
// rather than 32.
//
// The values are hex, like the 12C challenge: the TTC parameter carries them
// as text.
struct O5Logon11GChallenge {
    // The salt: the bytes of AUTH_VFR_DATA, which is 10 bytes on 11.2.
    std::string salt_hex;
    // The server's encrypted session key (48 bytes of ciphertext).
    std::string server_session_key_hex;
    uint32_t verifier_type = 0;
    // Whether the server's keys are padded. 11G strips PKCS#5 padding only
    // when the capability table says so: (ServerCompileTimeCaps[4] & 2) == 0.
    bool padded = true;
};

struct O5LogonResponse {
    std::string client_session_key_hex;
    std::string speedy_key_hex;
    std::string encrypted_password_hex;
    std::vector<uint8_t> combo_key;
};

O5LogonResponse BuildO5LogonResponse(const std::string &password, const O5LogonChallenge &challenge,
                                     const std::vector<uint8_t> &client_session_key,
                                     const std::vector<uint8_t> &password_salt,
                                     const std::vector<uint8_t> &speedy_key_salt);

// Builds the 11G (verifier 0x1B25 / 0xB152) O5LOGON response.
//
// The algorithm, byte for byte:
//
//   key      = SHA1(password || salt) || 00 00 00 00      (24 bytes = AES-192)
//   server   = AES-192-CBC-decrypt(key, IV=0, EServerSessKey)
//   client   = AES-192-CBC-decrypt(key, IV=0, EClientSessKey)
//   buffer   = server[16:40] XOR client[16:40]            (24 bytes)
//   combo    = (MD5(buffer[0:16]) || MD5(buffer[16:24]))[:24]
//   password = AES-192-CBC-encrypt(combo, IV=0, random16 || password)
//
// The password takes part exactly as given: it is not upper-cased and not
// re-encoded.
//
// The client session key is generated here (40 random bytes) and only its
// encrypted form is returned. A test may pass one in to make the output
// deterministic; an empty vector means "generate one".
O5LogonResponse BuildO5Logon11GResponse(const std::string &password, const O5Logon11GChallenge &challenge,
                                         const std::vector<uint8_t> &client_session_key = {});
bool VerifyO5LogonServerResponse(const O5LogonResponse &response, const std::string &server_response_hex);

} // namespace oracle_scanner
