# Provenance and reuse ledger

This project speaks Oracle's TNS/TTC protocol without any Oracle client, so two
questions have to have written answers: where the protocol knowledge came from,
and what evidence is stored in this repository. A rule that no wire behavior
ships without capture-backed evidence carries the obligation to account for the
evidence itself.

## What is reused, and under what terms

| Source | What is taken | Terms |
| --- | --- | --- |
| DuckDB extension template and `extension-ci-tools` | the build system, the loadable-extension scaffolding, and the CI distribution pipeline | MIT |
| DuckDB itself (submodule, pinned `v1.5.6`) | linked as a library; `duckdb_miniz` is compiled from its vendored copy for bounded in-memory wallet ZIP reading | MIT |
| OpenSSL | linked, not vendored: TLS transport and the digest and cipher primitives O5LOGON needs | Apache-2.0 |
| python-oracledb Thin | **reasoning and invariants, not code and not bytes.** It is the upstream of the protocol invariants recorded in comments throughout `src/`: which field, bit or length a client sends, and what breaks otherwise. | Apache-2.0 / UPL |
| go-ora (`github.com/sijms/go-ora`, commit `360b4b7ac9e96cee3e443180f2d6412bcacee62a`) | **reasoning, not code and not bytes.** A second reading of the listener exchange for multi-address connects: where REDIRECT data sits (inline after a UB2 length, or in the next DATA packet), its NUL between address and reconnect data and the 0x02 flag that announces it, the 0x04 flag on a re-CONNECT, and `(ERR=...)` in a REFUSE. Checked against python-oracledb Thin at commit `4a6d3b393232f6c5d66a497b7d137aa427f289d8` (`connect.pyx`, `connection.pyx`, `connect_params.pyx`), which is also where the FAILOVER / LOAD_BALANCE selection rules come from. Where the two differ, the code says which it follows and why. | MIT |

**No Oracle client software is used or distributed.** No OCI, Instant Client,
ODPI-C, ODBC, JDBC, Python runtime, or helper process is linked, loaded, or
shipped. `scripts/check_no_oracle_client.sh` inspects the built extension for
exactly that and fails if it cannot perform the inspection.

A protocol invariant carried over from elsewhere is evidence, not a
specification: anything load-bearing is confirmed against a live 19c or 23ai
database, or against an independent control, before it ships. Where a capture
disagreed with the source it came from, the disagreement is written down —
including the cases where the source was right, since knowing which side was
correct is worth as much as the defect.

## Captured bytes stored in this repository

Every byte sequence below was recorded from a server this project was tested
against. None contains a credential, a verifier, a wallet, a service name, a
host, or a port: the fetch and DML captures carry only test-table values and
Oracle-internal row addresses, and the negotiation template is a client request
sent before authentication.

Hashes are produced by `scripts/capture_inventory.sh`, which parses the byte
literals out of the source and digests them. If a hash below stops matching,
that is a fixture that changed — say why here rather than replacing the number,
because a fixture edited to make a test pass is otherwise indistinguishable from
one that records what a server sent.

| Capture | Bytes | Recorded from | SHA-256 |
| --- | --- | --- | --- |
| `zero_width_two_columns` | 14 | Oracle 19c, fetch response for `SELECT '' AS e, 'x' AS f FROM dual` | `fd8bd44b1c49811c5cd23743e20a315e0a56e7125d73d8339282375743595fba` |
| `zero_width_one_column` | 12 | Oracle 19c, fetch response for `SELECT '' AS e FROM dual` | `18d850b22a30ee38120ec1b3e9cf4c50e7b891034fcb6e2f16785efec1a98894` |
| `repeated_rows_fetch` | 85 | Oracle 19c, the second OFETCH of a one-column scan whose consecutive rows repeat | `e25dd1c6dbbd907ec2ac79b0ef7463555d960898723621241005c1251b77fda7` |
| `dml_end_of_call_one_row` | 59 | Oracle 19c, the end-of-call of `INSERT INTO t (id, label) VALUES (:1, :2)` run once | `d0ab7d8deca67ff7128421c88549b207001da719618ddfebd3349a785a1ba6c5` |
| `dml_end_of_call_three_rows` | 61 | Oracle 19c, the same statement run as three array-DML iterations | `a65853b671faf597dc98ff07266a5403f4c966fe5e8b9a7798ced2a36d232668` |
| `ttidty_negotiation_table` | 2642 | Oracle 19c, the TTIDTY/FDO capability request of a python-oracledb Thin pre-auth connection | `f264d0cdacb3465e48fe5cd71be86a42318f9a4056bf91bc776018323b367320` |
| `lob_row_one_clob` | 196 | Oracle 19c, fetch response for a single-row `SELECT` of one CLOB column | `b093b740172362a0c1db3493f07b67e02d0423f284bf4fdaa0c204e7642f758e` |
| `lob_rows_with_bit_vector` | 558 | Oracle 19c, fetch response for four rows of one CLOB column, where every row after the first arrives behind a BIT_VECTOR | `883809d2ce8d76825afcebf4cdc61fc4bd793f621a00035eb5065fa6c5891dde` |
| `lob_get_length_response` | 151 | Oracle 19c, the LOB_OP GET_LENGTH response for a ten-character CLOB | `79ca06d9b2b0e87a50d055cf9247c91aeed04705fcd32e83c1fa03c33e6f40a0` |
| `lob_read_clob_response` | 176 | Oracle 19c, the LOB_OP READ response for the same CLOB, ten Cyrillic characters in AL16UTF16 | `be443b3bcbabcb9d54ade98ff875d674e107175c0b566474b37d4bbd20c12d0f` |
| `lob_read_blob_response` | 157 | Oracle 19c, the LOB_OP READ response for a one-byte BLOB | `25ce01892864c504fd42ff03a9c0ccf3bd70bd6078260411dc0ea04af6dc8401` |
| `plain_rowid_fetch` | 78 | Oracle 19c, fetch response for `SELECT id, r` over a ROWID column: one row, then a NULL ROWID. The text decoded from the first row matches `ROWIDTOCHAR` of the same row on 19c and Free | `daf4a79391f84d674c60351db0cae2b0d343bc23eb20b72475317e5e9fc2c1c5` |
| `physical_urowid_fetch` | 82 | Oracle 19c, the same for a UROWID column holding a physical rowid, then a NULL | `a5406773617217035a2ce9d45310fa729c0f7552e7b932746097c33c00a529b5` |
| `logical_urowid_fetch` | 93 | Oracle 19c, the same for a UROWID column holding the rowids of an index-organized table. It frames like a physical one and is not decoded | `794ddd566c13a80c9ab55e7db2e9410d219e3ed910d328d3d7a150ae277b1346` |
| `long_fetch` | 92 | Oracle 19c, fetch response for `SELECT id, l` over a LONG column: `short`, then NULL, which arrives as an indicator of -1 and return code 1405 | `9acd33da9a3f85cb107a61c8dcfc491bbaf1ff7fc3ff4222ad2b0dd10fe07aac` |
| `long_raw_fetch` | 81 | Oracle 19c, the same for a LONG RAW column holding `DEADBEEF` | `96283a6c136e129b211d2245378f5a1d39290c6b707b5fe5499e1f5e6447874a` |
| `long_middle_fetch` | 109 | Oracle 19c, fetch response for `SELECT a, l, b` over three rows where the LONG sits between two other columns and holds a value, NULL and a value, the third row behind a BIT_VECTOR | `809f7b2d1d83a1c49ce4f1c4e2e4029b8bca5e2bcffd812f68fed3d22055d06e` |
| `interval_ym_value_bytes` | 15 | Oracle 19c and Free, three INTERVAL YEAR TO MONTH values: `2-3`, `-5-11`, `0-0` | `3b1f11e0c16f787be39958da84045a434a4d0a86e3325c38bc51dce8c6d9a0d5` |
| `interval_ds_value_bytes` | 33 | Oracle 19c and Free, three INTERVAL DAY TO SECOND values: `3 04:05:06.789012345`, `-12 23:59:59.5`, `0 0:0:0` | `0fa30cc86aff9f31922dba84155fa5c923a59cf688758fc7a452db6b2a0e8a09` |
| `nvarchar_value_bytes` | 30 | Oracle 19c and Free, one NVARCHAR2 value in UTF-16BE, ending in a surrogate pair | `4b91f33a7bdcccc78e7faeedae3566cbd49c6be8842dbe1920f098db696e3ee0` |

Live test databases are external and are named here only by the environment
variables that supply them; see [README.md](README.md). Nothing about an
endpoint is recorded in this repository.

## Synthetic fixtures

The multi-address and redirect tests in `test/cpp/protocol_test.cpp` build
their REDIRECT, REFUSE, ACCEPT and DATA packets in the test from the field
layouts named above. They are not captures, carry no bytes from any server or
client, and so are not inventoried with a hash; the tests say so where they
are defined. None of them has been checked against a live RAC or SCAN listener.
