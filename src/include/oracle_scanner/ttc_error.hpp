#pragma once

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

constexpr uint8_t TTC_MESSAGE_ERROR = 4;
// Server field version at or above which the end-of-call carries a SQL type
// and a server checksum between the extended row count and the message text.
constexpr uint8_t TTC_FIELD_VERSION_ERROR_TRAILER = 14;

// This is intentionally a diagnostic projection, not a full decoder for the
// version-dependent TTIOER body. It is safe to use when a TTC operation fails
// and preserves the ORA code when the server includes one in its text.
struct OracleServerError {
    std::optional<uint32_t> ora_code;
    std::string message;
};

// Structured prefix decoder for the versioned TTIOER body used by EXECUTE
// and PL/SQL responses. Unlike OracleServerError's diagnostic projection, it
// consumes exactly one TTC ERROR message so a response dispatcher can safely
// continue to the following STATUS message.
struct TtcErrorInfo {
    uint32_t error_number = 0;
    uint32_t cursor_id = 0;
    // Which iteration of an array DML the server was on. Zero-based, and only
    // meaningful when the call failed: for a batch it names the row that made
    // it fail, which is otherwise unrecoverable from the ORA- text.
    uint32_t current_row = 0;
    uint64_t row_count = 0;
    std::string message;
    size_t bytes_consumed = 0;
};

// A failed DML, carrying the iteration the server was on. Array DML runs one
// statement per row from a single request, so without this the caller is told
// that a batch of a thousand rows violated a constraint and nothing about
// which row did it.
class OracleDmlError : public ProtocolError {
public:
    OracleDmlError(uint32_t failed_row_p, const std::string &message,
                   std::optional<uint32_t> oracle_code = std::nullopt)
        : ProtocolError(ProtocolErrorKind::INVALID_STATE, message, oracle_code), failed_row(failed_row_p) {
    }

    //! Zero-based index of the iteration that failed.
    uint32_t FailedRow() const {
        return failed_row;
    }

private:
    uint32_t failed_row;
};

bool IsTtcErrorMessage(const std::vector<uint8_t> &message);
OracleServerError ParseTtcServerError(const std::vector<uint8_t> &message);
// Decodes one TTIOER body. A legacy (11.2) session uses a different layout
// for that body, so the caller must say which one applies; guessing produces
// a universal-integer width error instead of the server's own message.
TtcErrorInfo DecodeTtcErrorPrefix(const std::vector<uint8_t> &message, uint8_t ttc_field_version = 12,
                                   bool legacy_session = false);

// Decodes the TTIOER body of a legacy (11.2) session. The layout is not the
// 12C one: the legacy summary carries the end-of-call status and the
// end-to-end sequence ahead of the row counter, keeps the ORA number in the
// return code itself, and ends the fixed part with four length-prefixed
// blobs instead of the 12C rowid/batch arrays. A 12C decoder walks off the
// end of the body at the text length and reports a universal-integer width
// error instead of the server's own message.
//
// The layout was derived from go-ora's legacy summary reader and verified
// byte-for-byte against two live 11.2 error responses (ORA-00904 and
// ORA-03120): the decoded text ends exactly on the last byte of the body.
// `chunk_encoding` says how the session states the length of a long value:
// a universal integer on 19c and later, one raw byte on 11.2. The error text
// is such a value, so an 11.2 session that sends a long one has to be read
// that way.
TtcErrorInfo DecodeTtcLegacyErrorPrefix(const std::vector<uint8_t> &message,
                                         TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger);
[[noreturn]] void ThrowTtcServerError(const std::vector<uint8_t> &message);

} // namespace oracle_scanner
