#pragma once

#include <cstdint>

#include "oracle_scanner/byte_buffer.hpp"

namespace oracle_scanner {

// The session dialect. Oracle's TTC wire has changed shape across releases,
// and the differences are not cosmetic: a listener reads several of these
// messages POSITIONALLY, so one extra or one missing byte shifts every field
// after it and the request is rejected before the statement is even read.
//
// A dialect is therefore a value, not a flag threaded through a dozen
// signatures. It is derived once -- from the TNS accept version the listener
// answered with -- and then handed to the code that writes or reads a
// message. Every function that has to know the dialect takes it as one
// argument, so a new field on the dialect is a compile error at each place
// that has to decide about it, rather than a silent default.
//
// Two dialects exist:
//
//   * ModernDialect  -- 12.1 and later, which is what the extension was
//     originally written against. Long values state each piece's length as a
//     universal integer; the describe response carries an OACCOLID; the
//     execute request has the 12.2 tail layout.
//
//   * Legacy112Dialect -- 11.2 and earlier. Long values state each piece's
//     length as ONE RAW BYTE; the describe response has no OACCOLID; the
//     execute request has the 11.2 tail layout, which is seven bytes shorter.
//
// What the two dialects SHARE is stated in this file too, and it is stated
// positively: the shared part is the code that lives in the protocol
// functions themselves, unchanged, and this file only names the differences.
//
// References for every claim below:
//
//   * go-ora v1 (sijms/go-ora, repository ROOT -- not v2/ or v3/) is the
//     only open-source client that speaks 11.2 end to end. Its
//     network/session.go keeps ONE flag for the long-value encoding
//     (UseBigClrChunks) and consults it in exactly two places: GetClr (read)
//     and WriteClr/PutClr (write). Every value that goes through a CLR
//     inherits it. That is the model this class follows: one session-wide
//     choice, not a per-message one.
//
//   * go-ora v2/v3 and python-oracledb (thin) are 12.1+ only and are the
//     reference for the modern dialect.
//
//   * The capture of a real 11.2 listener is what fixes the legacy numbers.
//     A 11.2 session negotiates TTC field version 6 (server compile
//     capability byte 7), and its long value frames read "fe 40 <64 bytes>
//     20 <32 bytes> 00".
//
// The capability table must NOT be used to pick the dialect: a real 19c
// capture has capability byte 37 equal to 0xb8, and the bit go-ora v2/v3
// tests to choose the big-chunk encoding is set in it. Only the session's own
// TNS accept version says which dialect the listener speaks.

struct TtcDialect {
    // How the session states the length of one piece of a long value. This is
    // a property of the SESSION, not of an individual value: go-ora keeps
    // one flag for the whole session and consults it in the one reader and
    // the one writer.
    TtcChunkEncoding chunk_encoding = TtcChunkEncoding::UniversalInteger;

    // Whether the describe response carries an OACCOLID after the column's
    // maximum character size. 12.2 and later do; 11.2 does not. Reading the
    // field on a legacy listener shifts every later field by four bytes, and
    // the name that comes out is the declared length of the text rather than
    // the text itself.
    bool describe_has_oaccolid = true;

    // Whether the BIND METADATA written in an execute request carries an
    // OACCOLID. This is a different field from the describe response's, and
    // it is version-gated rather than dialect-gated on the modern side:
    // 12.2 and later write it, earlier ones do not. The legacy side has no
    // OACCOLID in bind metadata at all, for the same reason its describe
    // response has none.
    //
    // The listener reads bind metadata POSITIONALLY, so the extra byte
    // becomes the NEXT BIND'S DATA TYPE. A bind type of zero is not a type
    // Oracle can put on the wire, so the server rejects the whole request
    // with ORA-03115 ("unsupported network datatype or representation")
    // before it ever looks at the statement. go-ora v1 writes no OACCOLID
    // either.
    bool bind_metadata_has_oaccolid = true;

    // Whether the execute request's closing tail uses the legacy layout.
    // The two layouts are different lengths, and the difference is not
    // cosmetic: the SQL text and the al8i4 array that follow sit at
    // different offsets, so a legacy listener reads them from the wrong
    // place and answers with an internal conversion error instead of the
    // statement's result.
    bool execute_tail_legacy = false;

    // The call sequence byte in an execute request. A modern session states
    // the sequence there; a legacy listener reads that position as part of
    // the request's own header instead, and go-ora -- which supports 11g and
    // writes zero there for every version -- is the reference for what it
    // expects.
    bool zero_execute_sequence = false;

    // The number of rows to prefetch. A legacy listener is told this in the
    // same place go-ora and the JDBC driver put it, and both use ten. The
    // modern form keeps the caller's own value.
    uint32_t legacy_prefetch_rows = 0;

    // Whether the listener wants the Additional Network Option negotiation
    // before the TTC negotiation. A legacy listener does, and skipping it
    // leaves the listener waiting -- which is what turned 11.2 into a
    // connection that timed out with nothing to report.
    bool requires_ano_negotiation = false;

    // The service options and connect flags in the CONNECT packet header.
    // These are NOT a dialect difference in the message layout, but they are
    // a difference in what the listener accepts: the values the modern
    // client sends get an ACCEPT and then silence on the next request from
    // an 11.2 listener, while the values the official driver sends are
    // answered.
    uint16_t connect_service_options = 0x0001;
    uint16_t connect_connect_flags = 0x8484;

    // The service name in the connect descriptor, uppercased. The legacy
    // listener matches the SERVICE_NAME literally.
    bool uppercase_service_name = false;

    // Whether the connect descriptor is written inline in the CONNECT
    // packet. A legacy listener requires it there.
    bool inline_connect_descriptor = false;

    // The error body shape. The 11.2 TTIOER summary has two extra leading
    // fields (end-of-call status, end-to-end sequence), takes the ORA number
    // from the return code rather than from a later error-number field, ends
    // its fixed part with four length-prefixed blobs, and has neither a row
    // count nor a trailing SQL type and checksum. A modern decoder cannot
    // read it and a legacy decoder cannot read a modern body, so the two are
    // separate functions rather than one function with a branch.
    bool legacy_error_body = false;

    // Whether a query's execute request carries the FETCH option bit (0x40).
    //
    // The two dialects disagree, and this is a REAL dialect difference, not a
    // mistake on either side:
    //
    //   * A legacy (11.2) listener must NOT see it. go-ora v1 -- the only
    //     open-source client that speaks 11g -- sets that bit only when a
    //     request neither parses nor executes
    //     (go-ora v1 command.go:404-406), and a request that parses and
    //     executes must leave it clear or the listener reads the request as a
    //     fetch from a cursor that was never opened.
    //
    //   * A modern listener MUST see it. python-oracledb Thin sets
    //     TNS_EXEC_OPTION_FETCH for a query that prefetches
    //     (python-oracledb src/oracledb/impl/thin/messages/execute.pyx:98-99,
    //     with TNS_EXEC_OPTION_FETCH = 0x40 in constants.pxi), and the bit
    //     sits ALONGSIDE the parse and execute bits there, not instead of
    //     them. The upstream 0.6.0 execute request therefore carries
    //     options 0x8067 for a query, and its own protocol test asserts
    //     that value.
    //
    // Dropping the bit from the modern path is not a harmless extra bit: the
    // server prefetches nothing, and the extension's own fetch path then
    // asks for rows the cursor was never told to produce.
    bool query_sets_fetch_bit = true;

    // Whether the describe response's scale field has to be found by
    // backtracking. 11.2 states a NUMBER column's scale in two widths within
    // the SAME session -- one signed byte ("81" is -127) and the compressed
    // signed integer ("81 7f" is -127 too) -- and the width is per-column
    // and varies. A type-gated fixed width is wrong; only a search that
    // requires every remaining column and the trailer to stay
    // self-consistent finds the width the server used.
    bool backtrack_scale_width = false;
};

// The modern dialect: 12.1 and later, which is what the extension was
// originally written against. The 19c capture and the 12.2 Thin OALL8
// capture agree on every field below.
constexpr TtcDialect ModernDialect() {
    TtcDialect dialect;
    dialect.chunk_encoding = TtcChunkEncoding::UniversalInteger;
    dialect.describe_has_oaccolid = true;
    dialect.bind_metadata_has_oaccolid = true;
    dialect.execute_tail_legacy = false;
    dialect.zero_execute_sequence = false;
    dialect.legacy_prefetch_rows = 0;
    dialect.requires_ano_negotiation = false;
    dialect.connect_service_options = 0x0001;
    dialect.connect_connect_flags = 0x8484;
    dialect.uppercase_service_name = false;
    dialect.inline_connect_descriptor = false;
    dialect.legacy_error_body = false;
    dialect.backtrack_scale_width = false;
    dialect.query_sets_fetch_bit = true;
    return dialect;
}

// The legacy dialect: 11.2 and earlier.
constexpr TtcDialect Legacy112Dialect() {
    TtcDialect dialect;
    dialect.chunk_encoding = TtcChunkEncoding::RawByte;
    dialect.describe_has_oaccolid = false;
    dialect.bind_metadata_has_oaccolid = false;
    dialect.execute_tail_legacy = true;
    dialect.zero_execute_sequence = true;
    dialect.legacy_prefetch_rows = 10;
    dialect.requires_ano_negotiation = true;
    dialect.connect_service_options = 0x0841;
    dialect.connect_connect_flags = 0x8181;
    dialect.uppercase_service_name = true;
    dialect.inline_connect_descriptor = true;
    dialect.legacy_error_body = true;
    dialect.backtrack_scale_width = true;
    dialect.query_sets_fetch_bit = false;
    return dialect;
}

// Picks the dialect from the session's own TNS accept version. The accept
// version is what the listener answered with, so it is the one statement
// about the session that the listener itself made.
//
// Do NOT infer the dialect from a capability byte: a real 19c capture has
// capability byte 37 equal to 0xb8, and the bit go-ora v2/v3 tests to choose
// the big-chunk encoding is set in it. A listener below 12.1 never sets the
// bit, and the accept version is what says so.
constexpr TtcDialect DialectForAcceptVersion(uint32_t accept_version) {
    // 314 is the accept version of the last release that speaks the legacy
    // session dialect. A 11.2 listener answers with 314 or lower; a modern
    // one answers with a higher version.
    constexpr uint32_t LEGACY_SESSION_MAX_TNS_VERSION = 314;
    return accept_version <= LEGACY_SESSION_MAX_TNS_VERSION ? Legacy112Dialect() : ModernDialect();
}

} // namespace oracle_scanner
