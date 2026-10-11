# Native shared CLOB regression (DRV-002)

The session call mutex must cover request sequence allocation as well as the
request/response pair. `NativeOracleCursor::ReadWholeLob` allocated a shared
non-atomic sequence before `LobOperation` acquired this mutex. Another cursor's
Fetch or session Query could race with it, or allocate/send out of order.
The fix acquires the existing recursive call lock before GET_LENGTH allocation
and holds it through the whole LOB read, including its chunks. Request encodings,
parsers, wallet verification and Cancel behavior are unchanged. A large LOB can
hold the channel longer; this is a correctness fix, not a performance claim.

The opt-in [regression](../test/cpp/shared_lob_live_test.cpp) opens one native
session, prepares four cursors and releases concurrent Fetch with a barrier.
Eight rounds require 32 exact CLOB results and successful cursor/session Close.
It uses SELECT TO_CLOB constants FROM DUAL only: no DDL/DML, schema creation,
proxy, packet fixtures, capture, injection or SQL/authentication retry. It never
prints exception text or configuration values. Each round prepares new cursors
after the prior successful round; failures terminate the operation.

```sh
ORACLE_SCANNER_TEST_TSAN=1 scripts/build_shared_lob_live_test.sh /tmp/shared-lob-test
# Set the environment locally, then run explicitly with a bounded supervisor.
/tmp/shared-lob-test
```

TCP requires `ORACLE_SCANNER_LOB_HOST`, `_PORT`, `_SERVICE`, `_USER`, `_PASSWORD`.
TCPS replaces host/port/service with `ORACLE_SCANNER_LOB_WALLET` and `_ALIAS`,
plus `_USER` and `_PASSWORD`. A wallet is read in memory, a single TCPS address
is required, and CA/hostname/server DN verification remains enabled. Connect
and read timeouts are 10/20 seconds; routing retries are disabled. Use an owned
process supervisor (120 s TCP / 240 s TCPS in acceptance), not an unbounded run.
Never put passwords in command arguments or commit wallet/endpoint values.

Acceptance on macOS arm64 (2026-10-06), upstream revision
`b4bc91343dd8b33d68e0d45d82c782acdd0c80f2`:

| Profile | Unfixed control | Fixed candidate |
|---|---|---|
| Oracle 19c TCP | 32/32 exact results; TSAN race, exit 66 | 32/32, no TSAN warning, exit 0 |
| Oracle Free TCP | 32/32 exact results; TSAN race, exit 66 | 32/32, no TSAN warning, exit 0 |
| ATP TCPS with verified wallet | Not run as a sanitizer control | 32/32, no TSAN warning, exit 0 |

The diagnostic stack identifies a one-byte write in NativeOracleCursor::Fetch
under its call mutex and the inlined LOB path without that mutex. Exact data
results alone do not pass the sanitizer gate. Race detection is scheduling
dependent; an earlier Free control had no warning. No connection retries or
server setting changes were used. The unchanged protocol suite passes with
the fixed translation unit, and the standalone regression and runtime sources
pass the Windows min/max/IN/OUT macro syntax check.

Isolated accepted fixed binary SHA256:
`5d01f92e968bddb66eee65c7b5e7a8cd31bd09c5cb6c71198d7c6c7332a9645e`.
The actual corrected upstream source was also built by the new script in
regular and TSAN modes using macOS Bash 3.2. Its TSAN executable passed the
19c public regression (32/32, no races, exit 0), SHA256:
`8854b11c8ceb8c92864b1e025df2b5c5cb0a687c594668e94c09ab870de4ac5d`.
The harness differs from the isolated candidate only in environment prefix.
The regular executable links OpenSSL and system C++ libraries, with no Oracle
client or Python runtime dependency.

Control binary SHA256:
`c5ba398be8d38284d52c83dab0e3a26ff97c9967f754746ab563abcb91c1c4cd`.
These hashes identify test builds, not a published driver release. Original
private logs remain outside version control. Linux/Windows runtime/TSAN,
DuckDB adapter, differential driver and full backend acceptance on the new
build remain open; these focused gates do not replace those lanes.

The separate Oracle DuckLake ATP empty-TTC incident (DRV-001) is still under
investigation. This race is confirmed, but its relationship to that incident
has not been established. The active backend diagnostic run continues with
its original immutable driver; it is not evidence for this new driver fix.
