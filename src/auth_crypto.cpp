// Before any include: OpenSSL's headers pull in <windows.h>, which defines min
// and max as macros. See openssl_stream.cpp.
#if defined(_WIN32) && !defined(NOMINMAX)
#define NOMINMAX
#endif

#include "oracle_scanner/auth_crypto.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <utility>

namespace oracle_scanner {

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static const EVP_CIPHER *CipherForKey(size_t key_size) {
    switch (key_size) {
    case 16:
        return EVP_aes_128_cbc();
    case 24:
        return EVP_aes_192_cbc();
    case 32:
        return EVP_aes_256_cbc();
    default:
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "AES-CBC key must contain 16, 24, or 32 bytes");
    }
}

std::vector<uint8_t> SecureRandomBytes(size_t size) {
    if (size == 0 || size > 1024 || size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "requested random material exceeds supported bounds");
    }
    std::vector<uint8_t> result(size);
    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL CSPRNG failed");
    }
    return result;
}

std::string Base64Encode(const std::vector<uint8_t> &value) {
    if (value.empty() || value.size() > 768) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "base64 input exceeds supported bounds");
    }
    std::string result(((value.size() + 2) / 3) * 4, '\0');
    const auto encoded_size = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(&result[0]), value.data(),
                                               static_cast<int>(value.size()));
    if (encoded_size <= 0 || static_cast<size_t>(encoded_size) != result.size()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL base64 encoding failed");
    }
    return result;
}

std::vector<uint8_t> Pbkdf2Sha512(const std::vector<uint8_t> &password, const std::vector<uint8_t> &salt,
                                  uint32_t iterations, size_t output_size) {
    if (iterations == 0 || iterations > 10000000 || output_size == 0 || output_size > 1024 ||
        password.size() > static_cast<size_t>((std::numeric_limits<int>::max)()) ||
        salt.size() > static_cast<size_t>((std::numeric_limits<int>::max)()) ||
        output_size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "PBKDF2 parameters exceed supported bounds");
    }
    std::vector<uint8_t> output(output_size);
    auto result = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char *>(password.data()), static_cast<int>(password.size()),
                                   salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations), EVP_sha512(),
                                   static_cast<int>(output.size()), output.data());
    if (result != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL PBKDF2-HMAC-SHA512 failed");
    }
    return output;
}

std::vector<uint8_t> Sha512(const std::vector<std::vector<uint8_t>> &parts) {
    EVP_MD_CTX *raw_context = EVP_MD_CTX_new();
    if (!raw_context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 allocation failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), EVP_sha512(), nullptr) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 initialization failed");
    }
    for (const auto &part : parts) {
        if (EVP_DigestUpdate(context.get(), part.data(), part.size()) != 1) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 update failed");
        }
    }
    std::vector<uint8_t> output(SHA512_DIGEST_LENGTH);
    unsigned int output_size = 0;
    if (EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1 || output_size != output.size()) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL SHA-512 finalization failed");
    }
    return output;
}

namespace {

// A one-shot digest over a single buffer. SHA-1 and MD5 are here only because
// the 11G password verifier needs them; 12C is PBKDF2-SHA-512 throughout.
std::vector<uint8_t> Digest(const EVP_MD *algorithm, const std::vector<uint8_t> &value, const char *what) {
    EVP_MD_CTX *raw_context = EVP_MD_CTX_new();
    if (!raw_context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL ") + what + " allocation failed");
    }
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(raw_context, EVP_MD_CTX_free);
    if (EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL ") + what + " initialization failed");
    }
    if (!value.empty() && EVP_DigestUpdate(context.get(), value.data(), value.size()) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL ") + what + " update failed");
    }
    unsigned int output_size = 0;
    std::vector<uint8_t> output(EVP_MAX_MD_SIZE);
    if (EVP_DigestFinal_ex(context.get(), output.data(), &output_size) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, std::string("OpenSSL ") + what + " finalization failed");
    }
    output.resize(output_size);
    return output;
}

} // namespace

std::vector<uint8_t> Sha1(const std::vector<uint8_t> &value) {
    return Digest(EVP_sha1(), value, "SHA-1");
}

std::vector<uint8_t> Md5(const std::vector<uint8_t> &value) {
    return Digest(EVP_md5(), value, "MD5");
}

static std::vector<uint8_t> AesCbc(const std::vector<uint8_t> &key, const std::vector<uint8_t> &input, bool encrypt,
                                   bool padding) {
    if (!encrypt && (input.empty() || input.size() % 16 != 0)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "AES-CBC ciphertext must be a non-empty block sequence");
    }
    CipherContext context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL AES-CBC allocation failed");
    }
    uint8_t iv[16] = {0};
    auto cipher = CipherForKey(key.size());
    if (EVP_CipherInit_ex(context.get(), cipher, nullptr, key.data(), iv, encrypt ? 1 : 0) != 1) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "OpenSSL AES-CBC initialization failed");
    }
    EVP_CIPHER_CTX_set_padding(context.get(), padding ? 1 : 0);
    if (!padding && (input.empty() || input.size() % 16 != 0)) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "raw AES-CBC input must be a non-empty block sequence");
    }
    if (input.size() > static_cast<size_t>((std::numeric_limits<int>::max)())) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "AES-CBC input exceeds supported bounds");
    }
    std::vector<uint8_t> output(input.size() + 16);
    int first_size = 0;
    int final_size = 0;
    if (EVP_CipherUpdate(context.get(), output.data(), &first_size, input.data(), static_cast<int>(input.size())) != 1 ||
        EVP_CipherFinal_ex(context.get(), output.data() + first_size, &final_size) != 1) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "OpenSSL AES-CBC operation or padding validation failed");
    }
    output.resize(static_cast<size_t>(first_size + final_size));
    return output;
}

std::vector<uint8_t> AesCbcEncrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext) {
    return AesCbc(key, plaintext, true, true);
}

std::vector<uint8_t> AesCbcDecrypt(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext) {
    return AesCbc(key, ciphertext, false, true);
}

std::vector<uint8_t> AesCbcEncryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext) {
    return AesCbc(key, plaintext, true, false);
}

std::vector<uint8_t> AesCbcDecryptRaw(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext) {
    return AesCbc(key, ciphertext, false, false);
}

std::string UpperHex(const std::vector<uint8_t> &value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string output(value.size() * 2, '0');
    for (size_t index = 0; index < value.size(); index++) {
        output[index * 2] = digits[value[index] >> 4U];
        output[index * 2 + 1] = digits[value[index] & 0x0fU];
    }
    return output;
}

std::vector<uint8_t> DecodeHex(const std::string &value, size_t maximum_bytes) {
    if (value.size() % 2 != 0 || value.size() / 2 > maximum_bytes) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "hex value is odd-sized or exceeds configured limit");
    }
    auto nibble = [](char character) -> uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<uint8_t>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<uint8_t>(character - 'A' + 10);
        }
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "hex value contains a non-hexadecimal character");
    };
    std::vector<uint8_t> output(value.size() / 2);
    for (size_t index = 0; index < output.size(); index++) {
        output[index] = static_cast<uint8_t>((nibble(value[index * 2]) << 4U) | nibble(value[index * 2 + 1]));
    }
    return output;
}

void RequireSupportedO5LogonVerifier(uint32_t verifier_type) {
    if (verifier_type == O5LOGON_VERIFIER_12C || verifier_type == O5LOGON_VERIFIER_11G_1 ||
        verifier_type == O5LOGON_VERIFIER_11G_2) {
        return;
    }
    char type[16];
    std::snprintf(type, sizeof(type), "0x%04X", static_cast<unsigned>(verifier_type));
    std::string kind;
    std::string remedy;
    if (verifier_type == O5LOGON_VERIFIER_11G_1 || verifier_type == O5LOGON_VERIFIER_11G_2) {
        kind = "the 11G password verifier";
        remedy = "The account needs a 12C password version: see PASSWORD_VERSIONS in DBA_USERS";
    } else if (verifier_type == O5LOGON_VERIFIER_10G) {
        // The server picks the case-insensitive 10G verifier whenever the
        // database runs with SEC_CASE_SENSITIVE_LOGON = FALSE, even for an
        // account that also has 11G and 12C versions. python-oracledb Thin
        // fails the same way (DPY-3015).
        kind = "the case-insensitive 10G password verifier";
        remedy = "The database most likely runs with SEC_CASE_SENSITIVE_LOGON = FALSE, which makes the server offer "
                 "10G even to accounts that have a 12C password version; ask the DBA";
    } else {
        kind = "an unknown password verifier";
        remedy = "The account needs a 12C password version: see PASSWORD_VERSIONS in DBA_USERS";
    }
    throw ProtocolError(ProtocolErrorKind::UNSUPPORTED,
                        "Oracle offered " + kind + " (type " + type +
                            ") for this account; oracle_scanner authenticates with the 12C verifier (type 0x4815) and the "
                            "11G verifiers (types 0xB152 and 0x1B25). " +
                            remedy);
}

O5LogonResponse BuildO5LogonResponse(const std::string &password, const O5LogonChallenge &challenge,
                                     const std::vector<uint8_t> &client_session_key,
                                     const std::vector<uint8_t> &password_salt,
                                     const std::vector<uint8_t> &speedy_key_salt) {
    if (password.empty() || password.size() > 1024 || client_session_key.size() != 32 || password_salt.size() != 16 ||
        speedy_key_salt.size() != 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid O5LOGON password or random material");
    }
    // The verifier first: an account whose verifier this client does not
    // implement is unsupported, not malformed, and has to be reported so.
    // There is no default — a challenge that does not say 12C is not 12C.
    RequireSupportedO5LogonVerifier(challenge.verifier_type);
    auto verifier = DecodeHex(challenge.verifier_data_hex, 64);
    auto encrypted_server_key = DecodeHex(challenge.server_session_key_hex, 64);
    auto combo_salt = DecodeHex(challenge.combo_key_salt_hex, 64);
    // Lengths, never contents: the values are key material.
    if (verifier.size() != 16 || encrypted_server_key.size() != 32 || combo_salt.size() != 16) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "malformed 12C O5LOGON challenge: verifier data " + std::to_string(verifier.size()) +
                                " bytes, session key " + std::to_string(encrypted_server_key.size()) +
                                " bytes, combo-key salt " + std::to_string(combo_salt.size()) +
                                " bytes; expected 16, 32 and 16");
    }
    if (challenge.verifier_iterations == 0 || challenge.verifier_iterations > 10000000 ||
        challenge.combo_key_iterations == 0 || challenge.combo_key_iterations > 10000000) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "malformed 12C O5LOGON challenge: a PBKDF2 iteration count is outside 1..10000000");
    }

    std::vector<uint8_t> password_bytes(password.begin(), password.end());
    std::vector<uint8_t> verifier_salt = verifier;
    static constexpr char speedy_key[] = "AUTH_PBKDF2_SPEEDY_KEY";
    verifier_salt.insert(verifier_salt.end(), speedy_key, speedy_key + sizeof(speedy_key) - 1);
    auto password_key = Pbkdf2Sha512(password_bytes, verifier_salt, challenge.verifier_iterations, 64);
    auto password_digest = Sha512({password_key, verifier});
    password_digest.resize(32);

    auto server_session_key = AesCbcDecryptRaw(password_digest, encrypted_server_key);
    auto encrypted_client_key = AesCbcEncryptRaw(password_digest, client_session_key);
    std::vector<uint8_t> combined = client_session_key;
    combined.insert(combined.end(), server_session_key.begin(), server_session_key.end());
    auto combined_hex = UpperHex(combined);
    std::vector<uint8_t> combined_hex_bytes(combined_hex.begin(), combined_hex.end());
    auto combo_key = Pbkdf2Sha512(combined_hex_bytes, combo_salt, challenge.combo_key_iterations, 32);

    std::vector<uint8_t> password_plaintext = password_salt;
    password_plaintext.insert(password_plaintext.end(), password_bytes.begin(), password_bytes.end());
    auto encrypted_password = AesCbcEncrypt(combo_key, password_plaintext);
    std::vector<uint8_t> speedy_plaintext = speedy_key_salt;
    speedy_plaintext.insert(speedy_plaintext.end(), password_key.begin(), password_key.end());
    auto speedy_ciphertext = AesCbcEncrypt(combo_key, speedy_plaintext);
    if (speedy_ciphertext.size() < 80) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON speedy-key ciphertext is truncated");
    }
    speedy_ciphertext.resize(80);
    return {UpperHex(encrypted_client_key), UpperHex(speedy_ciphertext), UpperHex(encrypted_password), std::move(combo_key)};
}

namespace {

// Strips PKCS#5 padding. The 11G session keys are 40 bytes, which is not a
// block multiple, so the padding is part of the key material and has to be
// removed explicitly.
std::vector<uint8_t> StripPkcs5(const std::vector<uint8_t> &value) {
    if (value.empty()) {
        return value;
    }
    const size_t count = value.back();
    if (count == 0 || count > 16 || count > value.size()) {
        return value;
    }
    for (size_t index = value.size() - count; index < value.size(); ++index) {
        if (value[index] != count) {
            return value;
        }
    }
    return std::vector<uint8_t>(value.begin(), value.end() - count);
}

} // namespace

O5LogonResponse BuildO5Logon11GResponse(const std::string &password, const O5Logon11GChallenge &challenge,
                                         const std::vector<uint8_t> &client_session_key) {
    if (password.empty() || password.size() > 1024) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "invalid O5LOGON password");
    }
    // The verifier decides the algorithm: 11G and 12C keys are derived
    // differently, so a challenge that says 12C must not be answered with the
    // 11G algorithm, and the other way round.
    RequireSupportedO5LogonVerifier(challenge.verifier_type);
    if (challenge.verifier_type != O5LOGON_VERIFIER_11G_1 && challenge.verifier_type != O5LOGON_VERIFIER_11G_2) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "the 11G O5LOGON response was asked for a challenge with a different verifier");
    }
    auto salt = DecodeHex(challenge.salt_hex, 128);
    auto encrypted_server_key = DecodeHex(challenge.server_session_key_hex, 256);
    if (salt.empty()) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "malformed 11G O5LOGON challenge: the salt is missing");
    }
    if (encrypted_server_key.empty() || encrypted_server_key.size() % 16 != 0) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "malformed 11G O5LOGON challenge: the encrypted session key is not a block sequence");
    }

    // key = SHA1(password || salt) || 00 00 00 00 -> 24 bytes, an AES-192 key.
    //
    // The password takes part exactly as given: it is not upper-cased and not
    // re-encoded. An 11.2 account whose password contains non-ASCII bytes
    // authenticates with those bytes.
    std::vector<uint8_t> password_bytes(password.begin(), password.end());
    std::vector<uint8_t> key_material = password_bytes;
    key_material.insert(key_material.end(), salt.begin(), salt.end());
    auto key = Sha1(key_material);
    key.insert(key.end(), 4, 0x00);
    if (key.size() != 24) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "the 11G O5LOGON key is not 24 bytes");
    }

    // The session keys are 40 bytes, which is not a multiple of the AES block
    // size: the server sends them as 48 bytes of ciphertext, and 48 bytes of
    // raw CBC plaintext is 40 bytes of key plus 8 bytes of PKCS#5 padding.
    //
    // So the cipher is used raw (no padding of its own) and the PKCS#5
    // padding is removed by hand -- and only when the capability table says
    // the keys are padded: (ServerCompileTimeCaps[4] & 2) == 0.
    auto decrypt_key = [&](const std::vector<uint8_t> &ciphertext) {
        auto plain = AesCbcDecryptRaw(key, ciphertext);
        if (!challenge.padded) {
            if (plain.size() < 40) {
                throw ProtocolError(ProtocolErrorKind::MALFORMED,
                                    "malformed 11G O5LOGON challenge: the decrypted session key is shorter than 40 bytes");
            }
            return std::vector<uint8_t>(plain.begin(), plain.begin() + 40);
        }
        return StripPkcs5(plain);
    };
    auto server_session_key = decrypt_key(encrypted_server_key);
    // The client session key is ours: 40 random bytes, of which the server
    // sees only the encrypted form. A caller may supply one to make the
    // output deterministic; an empty vector means "generate one".
    auto client_session_key_plain = client_session_key.empty() ? SecureRandomBytes(40) : client_session_key;
    if (client_session_key_plain.size() != 40) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "the 11G O5LOGON client session key must be 40 bytes");
    }
    // Both session keys must be at least 40 bytes: the combo key is taken
    // from bytes 16..40 of them.
    if (server_session_key.size() < 40 || client_session_key_plain.size() < 40) {
        throw ProtocolError(ProtocolErrorKind::MALFORMED,
                            "malformed 11G O5LOGON challenge: the decrypted session keys are shorter than 40 bytes");
    }

    // buffer = server[16:40] XOR client[16:40]
    std::vector<uint8_t> buffer(24);
    for (size_t index = 0; index < buffer.size(); ++index) {
        buffer[index] = static_cast<uint8_t>(server_session_key[16 + index] ^ client_session_key_plain[16 + index]);
    }
    // combo = (MD5(buffer[0:16]) || MD5(buffer[16:24]))[:24]
    //
    // The trailing [:24] matters: the two digests are 32 bytes together and
    // only the first 24 of them are used, so the second MD5 contributes just
    // its first 8 bytes. Using all 32 would derive a different key and the
    // server would reject the password.
    std::vector<uint8_t> first_half(buffer.begin(), buffer.begin() + 16);
    std::vector<uint8_t> second_half(buffer.begin() + 16, buffer.end());
    auto combo_key = Md5(first_half);
    auto combo_tail = Md5(second_half);
    combo_key.insert(combo_key.end(), combo_tail.begin(), combo_tail.begin() + 8);
    if (combo_key.size() != 24) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "the 11G O5LOGON combo key is not 24 bytes");
    }

    // The password the server receives: 16 random bytes, then the password,
    // then PKCS#5 padding. The randomness is what makes the ciphertext
    // different for the same password.
    auto random_prefix = SecureRandomBytes(16);
    std::vector<uint8_t> password_plaintext = random_prefix;
    password_plaintext.insert(password_plaintext.end(), password_bytes.begin(), password_bytes.end());
    auto encrypted_password = AesCbcEncrypt(combo_key, password_plaintext);

    // The client session key the server receives: the same session key,
    // encrypted under the same key. 11G sends the encrypted key, not the
    // plain one.
    // The client session key goes out the same way it came in: 40 bytes of
    // key, PKCS#5 padded to 48, encrypted raw.
    auto client_session_key_padded = client_session_key_plain;
    client_session_key_padded.insert(client_session_key_padded.end(), 8, 0x08);
    auto encrypted_client_key = AesCbcEncryptRaw(key, client_session_key_padded);
    // 11G has no speedy key: the parameter is not part of the response.
    return {UpperHex(encrypted_client_key), std::string(), UpperHex(encrypted_password), std::move(combo_key)};
}

bool VerifyO5LogonServerResponse(const O5LogonResponse &response, const std::string &server_response_hex) {
    // 12C derives a 32-byte combo key and 11G a 24-byte one; both are valid
    // AES key sizes, and the server proof is encrypted under whichever the
    // challenge asked for.
    if (response.combo_key.size() != 32 && response.combo_key.size() != 24) {
        throw ProtocolError(ProtocolErrorKind::INVALID_STATE, "O5LOGON response has no valid combo key");
    }
    auto ciphertext = DecodeHex(server_response_hex, 256);
    auto plaintext = AesCbcDecrypt(response.combo_key, ciphertext);
    static constexpr char proof[] = "SERVER_TO_CLIENT";
    return plaintext.size() >= 32 &&
           std::equal(proof, proof + sizeof(proof) - 1, plaintext.begin() + 16, plaintext.begin() + 32);
}

} // namespace oracle_scanner
