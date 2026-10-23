# What works, and what does not

The support surface of `oracle_scanner`, stated precisely enough to plan against.
[README.md](../README.md) is the introduction; this is the boundary.

Every "works" below was run against a live Oracle — 19.3 EE, OCI Autonomous, and
Free 23ai — and every "refused" is a refusal this extension raises by name, not
a guess about what Oracle would do. Where the three servers differ, it says so.

The governing rule behind most of the refusals: **anything this client cannot
prove it will do identically to Oracle, it refuses instead of approximating.**
A wrong number is worse than an error, so the boundary is drawn at proof.

---

## 1. Connecting

### Where it runs

Native builds: **Linux, macOS, Windows**. Those are what the live lanes and the
clean-machine gate exercise.

DuckDB: releases from 0.5.0 on are built for **DuckDB 2.0** only — from 0.5.1,
against the v2.0.0 release; 0.5.0 was built for a 2.0 pre-release. An extension
loads only into the DuckDB version it was built for. 0.4.0 is the last release for DuckDB 1.5.6.

**A WebAssembly build cannot connect to Oracle.** Not "is untested" — it is
refused, by name, at connect:

> the default Oracle transport needs a TCP socket, which a WebAssembly build
> does not have

The reason is the transport and nothing above it. TNS runs over a raw TCP
stream, and no browser WebAssembly runtime has one: a page gets `fetch`,
WebSocket, and WebRTC, none of which is a socket. So the refusal is a property
of where the code runs, not a gap in the protocol implementation.

Everything above the byte transport is already transport-agnostic —
`TnsClientConnection` holds a `ByteStream`, and the connect path opens one
through `OpenOracleTransport`, so a different transport is installed rather than
threaded through. That seam exists and is tested. It is deliberately **not** a
WebAssembly port, and should not be read as most of one, because two things sit
outside it:

- **Every TTC exchange is a synchronous request and response.** `Receive()`
  blocks until a whole TNS packet arrives. Browser WebSocket APIs are
  callback-driven, and the main thread cannot block at all. Bridging that needs
  Asyncify (large binary cost, and it has to cover DuckDB's own call stack),
  JSPI, or a worker with `Atomics.wait` — the last requiring cross-origin
  isolation on the *hosting page*, which an extension cannot guarantee.
- **A WebSocket-to-TCP bridge is a helper process,** which this project excludes
  by definition. It also decides where Oracle TLS terminates: inside the tunnel
  (needs OpenSSL compiled to wasm) or at the bridge — and at the bridge, the
  bridge sees the password and every row in cleartext. That is a different trust
  model from the one stated in section 10, not an implementation detail.

Both are decisions to take deliberately. Neither is blocked on the code.

This has now been measured rather than assumed. Our own sources **do** compile
for `wasm32-emscripten`, and so does OpenSSL through vcpkg. What fails is the
link of the threaded target:

> `wasm-ld: error: --shared-memory is disallowed by libssl-lib-ssl_lib.o because
> it was not compiled with 'atomics' or 'bulk-memory' features`

That is a mismatch in how the dependency was built, not a limit of this code.
The wasm targets are excluded from the distribution matrix regardless, because a
build that links would still refuse at connect for the reason above, and an
artifact that always refuses is worse than no artifact.

### Database character set

Any. The client asks Oracle for AL32UTF8 during TTC negotiation and the server
converts, so a database in `TR8MSWIN1254`, `WE8MSWIN1252`, `ZHS16GBK` or
anything else hands over UTF-8 and takes UTF-8 back. Nothing has to be
configured, and the database's own character set is never a reason to refuse a
connection.

Verified live by creating a database in each and running the full protocol
lane against it — 18 stages each — plus reading and writing text that only
exists in that character set, checked from an independent session so that what
landed in the table is the database's own encoding rather than UTF-8 poured into
its columns:

| Database | Stored as | On the wire | Round trip |
| --- | --- | --- | --- |
| `TR8MSWIN1254` | 1 byte per character | UTF-8, 2 bytes | `ışğüöçİĞŞÇ` |
| `WE8MSWIN1252` | 1 byte per character | UTF-8, 2 bytes | `äöüßéàçñ`, `Größe: Straße` |
| `ZHS16GBK` | 2 bytes per character | UTF-8, 3 bytes | `数据库连接测试` |
| `AL32UTF8` | UTF-8 | UTF-8 | — |

Two limits remain, and neither depends on the database character set:
`NCHAR`/`NVARCHAR2` are refused because their values travel as UTF-16 in the row
(see §3), and characters outside the Basic Multilingual Plane — emoji, rare
ideographs — are untested, since none of the character sets above can hold one.

### Secrets

A connection is a DuckDB secret. The `DSN` field takes the same strings as
python-oracledb's `dsn`. An alias is looked up in `CONFIG_DIR`, else in the
wallet, else in the folder the `TNS_ADMIN` environment variable names.

```sql
CREATE SECRET ora (
    TYPE oracle,
    HOST '...', PORT 1521, SERVICE_NAME '...',
    USER '...', PASSWORD '...'
);
```

| Field | Meaning |
| --- | --- |
| `HOST`, `PORT`, `SERVICE_NAME` | The endpoint, given directly |
| `DSN` | One string, read as a full `(DESCRIPTION=...)` if it starts with `(`, as an Easy Connect string if it names a host or service (`host:port/service`), and otherwise as an alias |
| `TNS_ALIAS` | An alias resolved from `tnsnames.ora` in `CONFIG_DIR`, or else inside the `WALLET_FILE` |
| `MODULE`, `ACTION`, `CLIENT_IDENTIFIER`, `CLIENT_INFO` | End-to-end attributes sent once as the session opens, the way python-oracledb's `module`, `action`, `client_identifier` and `clientinfo` are, so a DBA sees which DuckDB job a session belongs to. Longer than 48, 32, 64 and 64 bytes is refused |
| `SID` | The database by SID instead of `SERVICE_NAME` (one of the two, not both); also `(CONNECT_DATA=(SID=...))` in a descriptor |
| `CONFIG_DIR` | A folder holding `tnsnames.ora`, or that file itself, for `TNS_ALIAS` or an alias given as `DSN` |
| `CONNECT_DESCRIPTOR` | A full `(DESCRIPTION=...)` inline; no wallet needed |
| `USER`, `PASSWORD` | Credentials |
| `PROTOCOL` | `tcp` (default) or `tcps` |
| `WALLET_FILE`, `WALLET_PASSWORD` | A cloud wallet ZIP, a wallet folder (`cwallet.sso` or `ewallet.pem`), or one of those two files; read in memory only |
| `TLS_CA_FILE`, `TLS_SERVER_NAME`, `TLS_SNI_NAME`, `TLS_SERVER_CERT_DN` | TLS material and the identity to check |
| `CONNECT_TIMEOUT`, `READ_TIMEOUT` | Socket timeouts; `CONNECT_TIMEOUT` is per attempt |

**Easy Connect**

`[tcp://|tcps://][//]host[:port][,host[:port]...]/service[:server][/instance][?key=value&...]`,
for example `tcps://db.example.com:2484/sales.example.com?retry_count=3`. It is
rewritten into the equivalent descriptor and judged by the same parser, so the
rules below apply to it unchanged. The port defaults to 1521 per host. The
parameters read are `failover`, `load_balance`, `retry_count`, `retry_delay`,
`transport_connect_timeout`, `connect_timeout` (whole seconds),
`ssl_server_cert_dn`, `ssl_server_dn_match`, and the accepted-and-ignored
`expire_time` and `sdu`. Any other parameter is refused by name. Values are not
percent-decoded, and a service name is required.

**Works**

- Plain TCP, and TCPS with a cloud wallet (`TNS_ALIAS` + `WALLET_FILE`) or with
  an explicit `TLS_CA_FILE`.
- Server DN matching (`TLS_SERVER_CERT_DN`), compared attribute by attribute so
  the RDN order OpenSSL prints and the order `tnsnames.ora` uses both match.
- The wallet ZIP is parsed in memory. Nothing is ever extracted to disk.
- **Several addresses, SCAN, and listener redirects — offline-tested only.**
  A descriptor (`CONNECT_DESCRIPTOR`, or a `TNS_ALIAS`) may name up to 16
  addresses in `ADDRESS` / `ADDRESS_LIST` entries. `FAILOVER`, `LOAD_BALANCE`
  (shuffled per new physical connection), `RETRY_COUNT`, `RETRY_DELAY`,
  `TRANSPORT_CONNECT_TIMEOUT` (per attempt) and `CONNECT_TIMEOUT` (read here as
  the budget for the whole connect) are honoured. Every IP a host name resolves
  to is its own attempt. A listener REDIRECT is followed — inline or in a DATA
  continuation, with or without reconnect data, re-CONNECT flagged 0x04 — for
  up to 3 hops, with loops refused and the rest of the configured addresses
  kept if the redirect target is down. A REFUSE's `ORA-` code is kept in the
  error. It is covered by a scripted listener and transport and by loopback
  sockets.

**Refused, by design**

- `TNS_ALIAS`, `CONNECT_DESCRIPTOR` and `HOST`/`PORT`/`SERVICE_NAME` — exactly
  one of the three.
- `DSN` beside `TNS_ALIAS`, `CONNECT_DESCRIPTOR`, `HOST`, `PORT` or `SERVICE_NAME`;
  `CONFIG_DIR` without an alias to look up; an alias with neither `CONFIG_DIR`
  nor `WALLET_FILE`; a descriptor with an address whose
  protocol disagrees with `PROTOCOL`; a `TRANSPORT_CONNECT_TIMEOUT` that
  disagrees with the secret's `CONNECT_TIMEOUT`.
- Descriptor settings whose meaning this client would silently drop:
  a `DESCRIPTION_LIST` whose descriptions name different databases,
  `FAILOVER_MODE` (TAF), `SOURCE_ROUTE=ON`, `SERVER=POOLED`, `HTTPS_PROXY`, a millisecond timeout, and any key it does
  not know. (`ENABLE`, `EXPIRE_TIME`, `SDU`, `TDU`, `SEND_BUF_SIZE`,
  `RECV_BUF_SIZE`, `TYPE_OF_SERVICE`, `USE_SNI` are accepted and ignored.)
- A listener redirect that changes the protocol — TCPS is never sent to TCP.
- Any `TLS_*` or `WALLET_*` field with `PROTOCOL 'tcp'`.
- Any `PROTOCOL` other than `tcp` or `tcps`.

**No bypass exists** for certificate or hostname verification. There is no
setting to turn it off, deliberately.

**Not supported:** the 11g SHA-1 verifier, Native Network Encryption (ANO),
`ewallet.p12`, SEPS, IAM tokens, failover of an established session (TAF), Application
Continuity, FAN/ONS, automatic retry of SQL, and proxy authentication. A lost
session fails the statement running on it; only new connections fail over.

---

## 2. The statement gate — read this before anything else

This is the limit people hit first, so it comes before the feature list.

Every SQL string handed to this extension goes through one gate:

| Function | Accepts | First keyword must be |
| --- | --- | --- |
| `oracle_query` | queries only | `SELECT`, `WITH` |
| `oracle_execute`, `oracle_execute_many` | DML only | `INSERT`, `UPDATE`, `DELETE` |
| `oracle_query_transaction`, `oracle_query_transaction_typed` | queries only | `SELECT`, `WITH` |
| `oracle_execute_transaction`, `oracle_execute_many_transaction` | DML only | `INSERT`, `UPDATE`, `DELETE` |
| `oracle_execute_composite_transaction` | 1 to 16 DML statements, each checked as above | `INSERT`, `UPDATE`, `DELETE` |
| `oracle_execute_admin` | one DDL command | `CREATE`, `ALTER`, `DROP`, `GRANT`, `REVOKE`, `COMMENT`, `TRUNCATE` |

And, in **all** cases:

> **A statement terminator `;` anywhere outside a string, a comment, or a
> `q'[...]'` literal is refused.**

The consequences are concrete and worth stating plainly:

- **Anonymous PL/SQL blocks have their own functions.** `BEGIN … END;` fails
  in the query and DML functions twice over: `BEGIN` is not an accepted first
  keyword there, and the `;` that PL/SQL itself requires is refused. `oracle_plsql`
  and `oracle_plsql_transaction` (§7) take a block; nothing else does.
- **DDL goes only through `oracle_execute_admin`.** The query and DML
  functions refuse `CREATE`, `DROP`, `ALTER` and `TRUNCATE`. `oracle_execute_admin`
  takes one such command, on a session of its own and never inside an explicit
  DuckDB transaction, because Oracle commits DDL implicitly. `CREATE OR REPLACE
  PROCEDURE` is still refused everywhere: a procedure body is full of
  semicolons.
- **`COMMIT` and `ROLLBACK` cannot be sent as SQL.** Transaction control is
  DuckDB's; see §6.

**Another way to run DDL**, one that predates `oracle_execute_admin`:

```sql
SELECT * FROM oracle_call_auto('ora', 'DBMS_UTILITY.EXEC_DDL_STATEMENT',
    ['CREATE TABLE t (id NUMBER(10), label VARCHAR2(50))']);
```

`DBMS_UTILITY.EXEC_DDL_STATEMENT` is an ordinary Oracle procedure taking one
`VARCHAR2`, so it goes through the callable path (§7) and never touches the SQL
gate. The DDL text it carries is not parsed here at all. The same trick runs
anything expressible as a single procedure call. For anything longer, or any
DDL, run a block with `oracle_plsql` (§7), which can `EXECUTE IMMEDIATE` it.

This is a real limitation, not a policy statement dressed up as one. It exists
because the gate is a whitelist of shapes whose bind, describe, and fetch
behavior this client has capture-backed evidence for.

---

## 3. Reading

```sql
SELECT * FROM oracle_query('ora', 'SELECT id, label FROM app.items');
```

### Bind parameters

An optional third argument carries binds. It is a **`LIST`** for positional
placeholders or a **`STRUCT`** for named ones — never loose trailing arguments.

```sql
-- named placeholders, :name
SELECT * FROM oracle_query('ora', 'SELECT * FROM t WHERE name = :name', {'name': 'nick'});

-- positional placeholders, :1 :2 — all of one type
SELECT * FROM oracle_query('ora', 'SELECT :1 AS a, :2 AS b FROM dual', ['hi', 'there']);

-- positional placeholders of mixed types: use a STRUCT keyed '1', '2', …
SELECT * FROM oracle_execute('ora', 'INSERT INTO t VALUES (:1, :2, :3)',
    {'1': 1, '2': 'one', '3': DATE '2026-01-02'});
```

The mixed-type case is the one that surprises: a DuckDB `LIST` literal is
homogeneous, so `[1, 'one', DATE '2026-01-02']` cannot even be constructed. A
`STRUCT` whose keys are `'1'`, `'2'`, … binds positionally and takes any mix.

### Column types

| Oracle type | Reads as | Notes |
| --- | --- | --- |
| `NUMBER(p,0)`, p ≤ 18 | `BIGINT` | |
| `NUMBER(p,s)`, s < 0, p − s ≤ 18 | `BIGINT` | Whole numbers rounded to a power of ten, `NUMBER(10,-2)` |
| `NUMBER(p,s)`, p ≤ 38, 1 ≤ s ≤ p | `DECIMAL(p,s)` | |
| `NUMBER(p,s)`, s > p, s ≤ 38 | `DECIMAL(s,s)` | Fractions with leading zeros, `NUMBER(2,4)` holds 0.0012 |
| `NUMBER` with no precision | `VARCHAR`, or what `oracle_unconstrained_number` says | Exact only as text; the setting trades that for `DOUBLE` or a fixed `DECIMAL` |
| `NUMBER` otherwise | `VARCHAR` | |
| `VARCHAR2`, `CHAR` | `VARCHAR` | Arrives as UTF-8 whatever the database character set is |
| `DATE` | `TIMESTAMP` | An Oracle `DATE` carries a time; it is not a DuckDB `DATE` |
| `TIMESTAMP(n)` | `TIMESTAMP`, or `TIMESTAMP_NS` when n > 6 | |
| `TIMESTAMP WITH TIME ZONE` | `VARCHAR` | The value carries its own offset, which `TIMESTAMPTZ` would drop |
| `RAW` | `BLOB` | |
| `BINARY_FLOAT`, `BINARY_DOUBLE` | `FLOAT`, `DOUBLE` | |
| `CLOB`, `NCLOB` | `VARCHAR` | See §4 |
| `BLOB` | `BLOB` | See §4 |
| `NCHAR`, `NVARCHAR2` | `VARCHAR` | UTF-16 in the row, read as UTF-8; written back as UTF-16 behind the national form. A filter on one is not pushed down |
| `INTERVAL YEAR TO MONTH` | `INTERVAL` | Whole months. A span past the 32-bit month count DuckDB keeps is refused. Written from an interval with months only |
| `INTERVAL DAY TO SECOND` | `INTERVAL` | Days and microseconds. Oracle keeps nanoseconds; a fraction finer than a microsecond is refused, not rounded. Written from an interval without months, whose days and time have one sign |
| `TIMESTAMP WITH LOCAL TIME ZONE` | `TIMESTAMPTZ` | An instant. The session time zone is UTC (see below), so the value Oracle sends is the instant. Microseconds only: a finer fraction is refused. Written from a `TIMESTAMPTZ` |
| `BOOLEAN` (23ai) | `BOOLEAN` | Needs a server that sends it as its own type, which 23ai does to a client advertising TTC field version 17, as this one does. Earlier servers have no such column |
| `JSON` (21c and later; read from 23ai) | `JSON` | The OSON image the server stores, decoded to JSON text. Objects keep the order the image holds. Oracle's non-JSON scalars print as `JSON_SERIALIZE` prints them: timestamps as ISO 8601 strings, `RAW` as upper-case hex, intervals as ISO 8601 durations. Written as its text, up to 1 GiB (past 8 MiB through a temporary LOB) |
| `VECTOR` (23ai) | `FLOAT[n]`, `DOUBLE[n]`, `TINYINT[n]`, `UTINYINT[n]`, or the same as a list | By the column's declared storage format and dimensions: `FLOAT32` is `FLOAT`, `FLOAT64` is `DOUBLE`, `INT8` is `TINYINT`, `BINARY` is the packed bytes as `UTINYINT` (dimensions ÷ 8). A fixed dimension count is an array, `*` a list. A column of any format (`VECTOR(*,*)`) is a list of `DOUBLE`, which holds every dense format but `BINARY`; a `BINARY` value in one is refused. A `SPARSE` column is `STRUCT(dimensions UINTEGER, indices UINTEGER[], "values" T[])`. Written as the image python-oracledb sends |
| `XMLTYPE` | `VARCHAR` | Through an attached table: the document as text, selected as `XMLSERIALIZE(CONTENT col AS CLOB NO INDENT)`, so it comes back compact whatever the storage. Written through `XMLPARSE(DOCUMENT :n)`, which gives NULL for NULL and Oracle's own `ORA-31011` for a document that does not parse. A filter on one runs in DuckDB. `oracle_query` of a bare `XMLTYPE` column is still refused: select `XMLSERIALIZE(...)` yourself |
| `ROWID`, `UROWID` | `VARCHAR` | The 18 characters Oracle itself prints (`ROWIDTOCHAR`). A logical UROWID, which an index-organized table has, is refused |
| `LONG` | `VARCHAR` | At most 1 MiB per value |
| `LONG RAW` | `BLOB` | At most 1 MiB per value |

The third row is the one people meet in practice. A column declared plain
`NUMBER` reads as `VARCHAR`, and on schemas generated by ETL or integration
tooling — where nearly every column is declared that way — a whole table comes
back without a numeric column. This is not a gap to be filled later: Oracle's
`NUMBER` is a base-100 decimal of up to 38 significant digits, `DOUBLE` cannot
hold one exactly (200,000 summed invoice amounts drift by about two cents), and
a fixed `DECIMAL(38,s)` has to choose an `s` and round anything longer. Text is
the only lossless form, so the value is handed over intact and the caller casts:
`CAST(col AS DECIMAL(38,6))` for money and anything reconciled, `CAST(col AS
BIGINT)` for keys, `CAST(col AS DOUBLE)` where a ratio is enough. Declaring the
column as `NUMBER(p[,s])` in Oracle removes the need entirely, and does so for
every client, not just this one.

There is no setting that changes this mapping. One was considered and refused:
a mode that silently narrowed unconstrained `NUMBER` would make correctness
depend on a flag, and a reconciliation that is exact in one session and two
cents off in another is worse than one that always asks for a cast.

**The session time zone is UTC.** Every session this extension opens sets
`TIME_ZONE='+00:00'` at login, as python-oracledb Thin sets its own client's
offset. A `TIMESTAMP WITH LOCAL TIME ZONE` reaches the client as a wall-clock
time with no offset, in the session's zone, so a fixed zone is what makes it an
instant. It also means `SESSIONTIMEZONE`, `CURRENT_TIMESTAMP` and the display of
a local-zone column in your own SQL are UTC in a session opened here. (Before
0.6.0 the zone was a fixed `+04:00`, copied from the capture the login was
modelled on, and nothing relied on it.)

**BOOLEAN, JSON and VECTOR need a newer field version.** This client advertises
TTC field version 24 (python-oracledb's `TNS_CCAP_FIELD_VERSION_23_4`) and uses
whatever the server will go to, up to that. A 23ai server then sends a SQL
`BOOLEAN` as itself (it needs 17; 13 to 16 still get `NUMBER`), tells the client
a `VECTOR` column's dimensions and storage format in the describe (it needs 24),
and sends JSON as an OSON image. From 18 every request header carries a token
number after its sequence number, which this client always sets to zero. A 19c
server reports 12 and negotiates down, so nothing changes there.

**JSON and VECTOR arrive with their rows.** A query over either gets a locator
for each value, and reading a value from its locator is a round trip of its own
or two. After the describe the client therefore re-executes the cursor with a
define for every column, the exchange python-oracledb makes, and asks for the
first 64 KiB of every JSON and VECTOR value ahead of its locator. A value longer
than that arrives cut short and the rest is read from the locator. On Free 23ai,
reading 5,000 rows of a `VECTOR(768,FLOAT32)` and a small `JSON` column took 1.5
and 1.4 seconds a column one value at a time and 0.3 and 0.04 with the define.
The define is only written when every column is a type whose define is known;
a table with a `ROWID` or `LONG` beside its JSON column is read value by value,
as before.

**A statement that writes a `JSON` column can carry text up to 1 GiB; one that
writes a `VECTOR` carries the image.** A vector as text would stop at the 32767
bytes of a `VARCHAR2` bind, about 2,700 `FLOAT32` elements, and embeddings of
3,072 and 4,096 dimensions are common. Neither can be returned by
`INSERT ... RETURNING`, which hands back a locator; that is refused by name.

**Refused while binding**, before any fetch, each naming its reason:

| Type | Why |
| --- | --- |
| `BFILE` | No read path |
| Object, `VARRAY`, nested table, `REF` | Outside this version |

A refusal happens at bind time, so a query either runs correctly or fails
immediately — it never returns a column decoded into something wrong.

An **attached** table (§5) still *lists* a column of an unsupported type — it
appears in `duckdb_columns()` with a nominal type — so the table is browsable.
Selecting that column raises, and so does `SELECT *` over the table. Name the
columns you can read and the rest of the table stays usable.

### Empty string

Oracle has no empty `VARCHAR2`: `''` is NULL. It does not round-trip — what goes
in as `''` comes back as NULL. That is Oracle's behavior, faithfully reproduced.

---

## 4. LOBs

`CLOB`, `NCLOB`, and `BLOB` are **read** and **written**. `BFILE` is neither.

**Writing** sends the content as an ordinary bind, as python-oracledb Thin does:
a `VARCHAR2` for a `CLOB` or `NCLOB` (Oracle converts to the national set
itself) and a `RAW` for a `BLOB`. Oracle accepts such a bind past the usual
32 767 bytes when its target is a LOB; the value goes out in chunks, and a bind
that wide has its value sent after the short ones in the row, which is the order
python-oracledb uses. Through an attached table that is `INSERT` and `UPDATE`
with a `VARCHAR` or `BLOB` value; an empty value is NULL, like any empty string
in Oracle.

- **Up to 8 MiB a value is an ordinary bind; past that, a temporary LOB.** The
  session creates one (`LOB_OP` `CREATE_TEMP`, for the session's duration),
  writes the content into it in pieces of at most 2 MiB (a `CLOB` as UTF-16, its
  offsets counted in UTF-16 units), binds its locator, and releases it when the
  statement is done, on failure too. In an array `INSERT` a column that needs one
  in any row of a group is bound by locator in every row of that group, because
  the bind metadata is declared once. The same shapes python-oracledb Thin sends
  (see PROVENANCE.md). A value is limited to **1 GiB**; the server's temporary
  tablespace is the real ceiling. Checked live to 100 MiB of `CLOB` and 200 MiB
  of `BLOB` against 19c and 23ai, content compared by hash.
- **Memory.** A statement is built whole, so a batch of N rows holds N times its
  LOB values at once; insert large LOBs a few rows at a time.
- **`RETURNING` cannot cover a LOB, JSON or VECTOR column.** Oracle returns a locator
  there, and DuckDB's `RETURNING` spans every column of the table, so a table
  with a LOB column refuses it with a message that names the column.
- A LOB column is not filtered remotely; a filter on one runs in DuckDB.

A LOB column carries a locator in the row. Against a server that negotiates
the 12c field version or later (19c, 23ai and Autonomous all do), the fetch asks Oracle to
send the first 4 096 characters or bytes of each LOB along with the row, in
batches of at most 128 rows and 4 MB; a value that fits costs no LOB call at
all, and a longer one reads only its remainder, 32 767 characters or 65 536
bytes per round trip. Where prefetch does not apply, every value costs its own
round trips: its first chunk, then the rest. Before prefetch, a local 19c took
**1.22 s** for 2 000 rows each holding a 2 000-character CLOB, against
**0.004 s** with the LOB column left out — round-trip bound, not bandwidth
bound. Long LOBs remain so.

**Select a LOB column only when you need it.** No other column type has a cost
profile remotely like this.

Verified live on all three servers: ASCII and non-Latin content, NULL against
empty (they stay distinct, as in Oracle), a 240 000-character CLOB and a
240 007-byte BLOB compared byte for byte against values rebuilt in DuckDB, and a
40 000-character NCLOB.

Character LOB content arrives as AL16UTF16 whatever the database character set
is, and is converted to UTF-8 here. `NCHAR` and `NVARCHAR2`
are different: their values travel in the row, as UTF-16, and are converted
there.

---

## 5. `ATTACH` — Oracle as a DuckDB catalog

```sql
ATTACH 'ora' AS o (TYPE oracle_scanner);
SELECT * FROM o.ITEMS WHERE id > 100;
```

The path is the **secret name**, not a connection string. One attachment exposes
one schema: the connected user's own tables and views, resolved lazily from
`USER_TABLES`, `USER_VIEWS`, and `USER_TAB_COLUMNS` — or, with `SCHEMA 'owner'`,
another user's, from `ALL_TABLES`, `ALL_VIEWS`, `ALL_TAB_COLUMNS` and
`ALL_CONSTRAINTS` filtered to that owner, with every statement qualified
(`"OWNER"."TABLE"`). The name is checked against `ALL_USERS` at `ATTACH` (exact,
else the single case-insensitive match; none is an error); naming the connected
user is the same as naming nothing. Only what the connected user can see is listed.

| Operation | Status |
| --- | --- |
| `SELECT` | Works |
| `INSERT`, `UPDATE`, `DELETE` | Works — see §6 |
| `INSERT … RETURNING` | Works |
| `UPDATE … RETURNING`, `DELETE … RETURNING` | Works, one statement per row, addressed by ROWID, with `SQL%ROWCOUNT` so a row already gone is left out |
| `CREATE TABLE`, `CREATE TABLE AS` | Refused — this extension issues no DDL |
| `DROP TABLE` | Refused |
| `CREATE SCHEMA`, `DROP SCHEMA` | Refused — one schema, and it is Oracle's |
| Another user's schema | Not exposed; use `oracle_query` with a qualified name |

Identifiers arrive as Oracle stores them, which is upper case unless they were
created quoted: `o.ITEMS`, not `o.items`.

### Filter pushdown

On by default; `SET oracle_filter_pushdown = false` turns it off.

DuckDB removes a filter from the plan once it hands it to a scan, so the scan
must apply every one *exactly*. Each filter is translated into the Oracle
`WHERE` clause only when its Oracle meaning is provably identical, and otherwise
kept and evaluated by DuckDB's own expression over each fetched batch — a
refusal costs speed, never an error. Translated: `=`, `<>`, `<`, `<=`, `>`, `>=`,
`IS NULL`, `IS NOT NULL`, `IN` (up to 1 000 values), and `AND`/`OR` over those,
on integer, decimal, date, and timestamp columns. Everything else is local: text
comparisons and `LIKE` (Oracle's collation and blank-padded `CHAR` comparison
depend on session settings this client does not negotiate), predicates across
several columns, `ROWID`, an `IN` list with one unprovable member.

**Join keys.** A join against a table DuckDB reads itself hands the scan the keys
of its other side as optional filters. A filter that is an `AND` of conjuncts is
read one conjunct at a time: an `IN` list or a range goes into the `WHERE`
clause, a prefix-range filter (DuckDB's bitmap of the keys) is turned back into
the key intervals it admits by asking it which ranges may hold a key — exactly,
as `IN` lists of single keys and `BETWEEN` ranges, up to 2,048 intervals, and as
a superset when there are more — and a bloom filter, which has no SQL form, is
dropped. All of them are hints, so dropping or widening one never changes an
answer. The choice of plan depends on the row count the catalog passes DuckDB,
`USER_TABLES.NUM_ROWS`, and on each column's `NUM_DISTINCT` (the distinct count only,
never a minimum, maximum or null count, which a stale statistic could make wrong in a
way that drops rows); a table without statistics has neither.

---

## 6. Writing and transactions

Two separate paths, with different rules.

### Through `ATTACH`

`INSERT`, `UPDATE`, and `DELETE` on an attached table participate in the DuckDB
transaction. One Oracle session is pinned to that transaction, so:

- A scan of the attached catalog inside the transaction **sees its own
  uncommitted rows**.
- `COMMIT` and `ROLLBACK` in DuckDB commit and roll back in Oracle. Verified:
  a row inserted inside a transaction is visible to a count in that same
  transaction and gone after `ROLLBACK`.

`UPDATE` and `DELETE` address rows by Oracle's `ROWID`, read as text — so the
target table needs no primary key, but the rows must still exist when the write
runs.

Values are encoded from the **Oracle** column type, never from the DuckDB type
alone, so nothing reaches Oracle as text for a session `NLS` setting to
reinterpret.

Writable column types: `VARCHAR2`, `CHAR`, `NCHAR`, `NVARCHAR2`, `NUMBER`,
`DATE`, `TIMESTAMP`, `TIMESTAMP WITH LOCAL TIME ZONE`, `INTERVAL YEAR TO MONTH`,
`INTERVAL DAY TO SECOND`, `BOOLEAN`, `RAW`, `BINARY_FLOAT`, `BINARY_DOUBLE`.
`CLOB`, `NCLOB`, `BLOB` (see §4), `JSON`, `VECTOR`. (`TIMESTAMP WITH TIME ZONE` is read but not
written.) Everything else — `LONG` and `ROWID` included — is refused by name. `FLOAT`/`DOUBLE` into a `NUMBER`
column is refused too: cast to `DECIMAL` or text first, because binary floats
are not exact.

### Session reuse between transactions

Each DuckDB transaction on an attached catalog still gets an Oracle session of
its own, held until its `COMMIT` or `ROLLBACK`. What changes with
`oracle_transaction_pool_size` (default 2) is where that session comes from: the
catalog keeps up to that many idle sessions, and the next transaction takes one
instead of connecting and authenticating again. The pool belongs to the attached
catalog, not to a DuckDB connection, so it serves transactions that each run on
a connection of their own — which is how DuckLake drives its metadata catalog.
Every session in it was opened from the one secret the catalog resolved at
`ATTACH`, so two catalogs, users or secrets never share one.

A session goes back only after Oracle acknowledged the transaction's `COMMIT` or
`ROLLBACK`, and only if it is clean: no statement still open, no cancel pending,
no exchange that failed, nobody else still holding it, and no stored procedure
run through `oracle_call_named_transaction` (which can change the session's own
state). Anything else is closed: a failed statement, a `COMMIT` whose outcome is
unknown, a rollback that failed. The dictionary reads `ATTACH` makes use the same
pool and end with a `ROLLBACK` before their session goes back.

Before an idle session is handed out it must answer `SELECT 1 FROM DUAL`. That
probe is the only thing sent on it before the transaction's own work, so a
session that died while idle — killed on the server, timed out — is replaced
without any statement of the transaction having been sent; once the transaction
has started, a failure is reported, never retried. Idle sessions are closed
after five minutes, and all of them when the catalog is detached. Each lease
follows its own caller's interrupt and IO deadline.

Not reset between transactions: package state a function called from a
`SELECT` may have changed. Statements that change session settings cannot be
sent through the transaction functions.

### Through `oracle_execute`

```sql
SELECT * FROM oracle_execute('ora', 'UPDATE t SET label = :1 WHERE id = :2', ['x', 7]);
SELECT * FROM oracle_execute_many('ora', 'INSERT INTO t VALUES (:1, :2)',
    [{'1': 1, '2': 'a'}, {'1': 2, '2': 'b'}]);
```

Both return `affected_rows`. **Both refuse to run inside an explicit DuckDB
transaction** — they autocommit in Oracle, which a DuckDB `ROLLBACK` could not
undo, so the mismatch is refused rather than hidden.

`oracle_execute_many` uses Oracle array DML: one execute carrying every
iteration, not one round trip per row. A row that fails reports its position.

### Raw SQL inside the attached transaction

For SQL the `ATTACH` path cannot express, seven functions take the attached
catalog's name instead of a secret and run on the session pinned to the DuckDB
transaction, so their work commits and rolls back with it:

- `oracle_query_transaction` — a query; it sees the transaction's own
  uncommitted rows. It learns its columns by running the query at bind, so a
  read runs it twice.
- `oracle_query_transaction_typed` — the same, with the result columns declared
  by the caller: bind sends nothing to Oracle, each execution runs the query
  once, and a describe that differs from the declaration in count, name or
  mapped type is an error. Declarable: `VARCHAR`, `BIGINT`, `DECIMAL(p,s)`,
  `DOUBLE`, `FLOAT`, `BLOB`, `TIMESTAMP`, `TIMESTAMP_NS`.
- `oracle_execute_transaction` — one `INSERT`, `UPDATE` or `DELETE`.
- `oracle_execute_many_transaction` — 1 to 2048 bind rows. Exact per-row counts
  by default, one execution per row; `exact_counts := false` sends array DML in
  groups of up to 1024 rows and returns one aggregate count.
- `oracle_execute_composite_transaction` — 1 to 16 `INSERT`, `UPDATE` or
  `DELETE` statements in one round trip, each with an exact expected row count
  that Oracle checks after it runs (`ORA-20906` on the first mismatch). Named or
  positional binds shared by all of them, each used; at most 256 binds, 64 KiB
  of SQL, 8 MiB of bind values, 1,000,000 expected rows per statement. A
  failure leaves the earlier statements applied in the transaction, which then
  needs `ROLLBACK`.
- `oracle_call_named_transaction` — a procedure with up to 64 `NUMBER` or
  `VARCHAR` arguments, `IN`, `OUT` or `IN OUT`, NULL included. No cursors, LOBs
  or objects. The procedure must not commit, run DDL or use an autonomous
  transaction.
- `oracle_plsql_transaction` — an anonymous PL/SQL block on the pinned session,
  with up to 64 binds (the same `STRUCT(name, direction, type, value)` as
  `oracle_call_named`), `IN`, `OUT` or `IN OUT`, returning one row per `OUT`
  bind. No cursors. The block must not commit, run DDL or use an autonomous
  transaction. The session ends closed rather than reused afterwards, because a
  block can change its state.
- `oracle_transaction_status` — the outcome of the current or last transaction
  (`commit_outcome`, `connection_state`, `oracle_error_code`,
  `protocol_error_kind`), read locally without opening a session. DuckDB drops
  the extra error fields when it wraps a failed `COMMIT` (1.5.6 did), so this is
  where they are.

None of them commits. A `READ_ONLY` catalog refuses the writing ones. A bind
that fails local validation is refused at bind time and leaves the transaction
untouched; a failure from Oracle invalidates the remote transaction, which then
needs `ROLLBACK`. A `COMMIT` that fails has an unknown outcome until checked.
Nothing is retried or replayed.

---

## 7. Calling procedures and functions

`oracle_call_auto` reads the signature from `ALL_ARGUMENTS` and binds
accordingly; the rest of the family is for callers who want to state the shape
themselves.

```sql
SELECT * FROM oracle_call_auto('ora', 'PKG.PROC', ['arg1', 'arg2']);
SELECT * FROM oracle_arguments('ora', 'PKG.PROC');   -- inspect the signature
```

**Works:** `IN`, `OUT`, and `IN OUT` arguments of `NUMBER`, `VARCHAR2`, `CHAR`,
`NCHAR`, `NVARCHAR2`, `DATE`, `TIMESTAMP`, `TIMESTAMP WITH LOCAL TIME ZONE`
(bound as the UTC wall time), `INTERVAL YEAR TO MONTH`, `INTERVAL DAY TO SECOND`
and `BOOLEAN` (a PL/SQL `BOOLEAN`, on a 23ai server); functions with a return value; `SYS_REFCURSOR` returns,
read through `oracle_cursor` and released with `oracle_close_call`; names
reached through a synonym; packaged and standalone callables.

**Refused:** arguments of LOB, object, record, collection, `REF`, `XMLTYPE`,
`JSON`, `VECTOR` or `TIMESTAMP WITH TIME ZONE` type; a name that matches more than one object; and an overload set with
two candidates of the same arity — only the caller can say which was meant.

A LOB is therefore **readable as a column but not passable as an argument.**

A procedure that commits internally is outside DuckDB's rollback guarantee, and
runs in its own call scope for that reason.

---

## 8a. Vector search

`oracle_vector_search(secret, table, column, query_vector, k := 10, metric := 'COSINE',
approximate := true)` returns the table's columns and `distance` for the `k` rows nearest
to the query vector, ranked by Oracle's `VECTOR_DISTANCE` (23ai). It orders by the
distance alias, which Oracle plans exactly as the expression: with a vector index the
plan is an index probe, not a scan. `k` is 1 to 100,000, `metric` one of six words
(never text from the caller), the identifiers are quoted. The query vector is sent in
the column's storage format, read from `VECTOR_INFO`, because Oracle refuses
`ORA-51812` on a mismatch; a `VECTOR(*,*)` column gets `FLOAT32` or `FLOAT64` by the
element type given. A server without `VECTOR` answers with its own error. It runs on a
pooled session of its own, not inside an attached transaction.

## 8. Parallel scan

**Attached tables, automatically.** `SET oracle_parallel_scan = N` lets a scan of an
attached table read through up to N sessions. It lists the table's extents
(`DBA_EXTENTS`, joined to `DBA_OBJECTS` for the data object), sorts them by ROWID order
(object, file, block), cuts between extents into about 4N chunks of equal blocks, and each
thread reads chunks as `ROWID >= lo AND ROWID < hi` (open at both ends) `AS OF SCN s`,
where `s` was taken once with `DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER`. Oracle plans
each as a `TABLE ACCESS BY ROWID RANGE`. Anything the plan needs and cannot get — the
extents, the change number, a flashback read, a heap table of 2,048 blocks or more —
means one stream, never an error, and so do a sample and a transaction that has written.
Partitioned tables work; the cut points run across partitions. Checked on 19c and 23ai by
`EXCEPT` both ways against the one-stream read, on a plain and a partitioned table, with
pushed filters, a local filter, `LIMIT` and `DELETE`.

**By key.** `oracle_scan_parallel` splits by ranges of a numeric key you name, and needs
no privilege beyond the table.

```sql
SELECT * FROM oracle_scan_parallel('ora', 'BIG_TABLE', 'ID', shards := 8);
```

Splits one table across several sessions by ranges of a numeric key. Every shard
reads `AS OF SCN` at one change number taken at bind time, so the shards are one
snapshot rather than several moments. A database that will not hand out a change
number is refused rather than scanned unpinned; if the snapshot predates a DDL
change to the table, Oracle's ORA-01466 is reported as such.

Requires a `NUMBER` key column with integral bounds. Rows whose key is NULL get
their own shard, so nothing is dropped.

---

## 9. Settings

| Setting | Default | Effect |
| --- | --- | --- |
| `oracle_session_pool_size` | `4` | Sessions pooled per DuckDB connection per secret identity, for reads. `0` disables pooling. |
| `oracle_transaction_pool_size` | `2` | Idle transaction sessions an attached catalog keeps; see §6. Read at `ATTACH`; `0` disables reuse. |
| `oracle_filter_pushdown` | `true` | See §5. |
| `oracle_deferred_columns` | `true` | When DuckDB applies a filter itself, CLOB/BLOB/JSON/VECTOR/XMLTYPE columns the filter does not read are fetched afterwards for the surviving rows, `WHERE ROWID IN (...)` at the change number the rows were read at; not for views, IOT/clustered/temporary tables, samples, parallel scans or a transaction that wrote |
| `oracle_join_pushdown` | `true` | An inner join of two attached tables of one database, compared on number, date or timestamp columns, becomes one statement over two inline views that carry each side's filters; not with a filter Oracle was not sent, a sample, or a LOB/JSON/VECTOR/XML/ROWID column |
| `oracle_aggregate_pushdown` | `true` | An AGGREGATE over an attached table (`count`, `sum` of exact numbers, `min`/`max`, group keys of numbers, dates and timestamps; no DISTINCT/FILTER/GROUPING SETS) is replaced by one `GROUP BY` statement, when every filter was sent to Oracle |
| `oracle_top_n_pushdown` | `true` | An `ORDER BY … LIMIT` over an attached table whose keys are all numbers, dates or timestamps is sent as `ORDER BY … NULLS FIRST/LAST FETCH FIRST (limit+offset) ROWS ONLY`; DuckDB's `TOP_N` still sorts the result. Not with a filter Oracle was not sent, a sample, or a parallel scan |
| `oracle_parallel_scan` | `-1` | Sessions one scan of an attached table may use, reading ROWID ranges cut at extent boundaries, all at one SCN (§8). `-1`: automatic (DuckDB's thread count, up to 8, when `NUM_ROWS` says 500,000 or more, else one); `0` or `1`: one stream |
| `oracle_unconstrained_number` | `'varchar'` | What a `NUMBER` with no declared precision (plain `NUMBER`, `SUM(x)`, `count(*)`) becomes: `'varchar'` (exact), `'double'`, or `'decimal(p,s)'` such as `'decimal(38,9)'`. Read when a query is bound or a table is first used; the lossy choices round what does not fit, and a DECIMAL that cannot hold a value's integer digits raises. A `DOUBLE` column then accepts `DOUBLE` on write |

Pooling matters more than it looks: opening a session costs a full TNS handshake
and authentication. Callables through a secret always open their own session;
the attached catalog's transactions reuse sessions as §6 describes.

---

## 10. Never, by construction

- **No Oracle client.** No OCI, Instant Client, ODPI-C, ODBC, JDBC, Python
  runtime, or helper process is linked or loaded. CI proves this on every build
  by inspecting the shipped binary.
- **No credential ever logged or persisted** — not passwords, verifier material,
  wallet passwords, keys, or bind values.
- **No wallet written to disk.** ZIPs are read bounded, in memory.
- **No TLS verification bypass.**

## 11. Not supported, in one list

DDL except through `oracle_execute_admin`, `DBMS_UTILITY.EXEC_DDL_STATEMENT` or a PL/SQL block ·
LOB values past 1 GiB · `BFILE` · a logical `UROWID` · writing `TIMESTAMP WITH TIME ZONE`,
`LONG` and `ROWID` · object, collection and record
types · several schemas in one attachment ·
`CREATE`/`DROP` through `ATTACH` · Native Network Encryption · the 11g SHA-1
verifier · SEPS · IAM · failover of an established session (TAF) ·
Application Continuity · AQ ·
distributed two-phase commit · WebAssembly builds (no TCP socket; see section 1)
· statement cancellation over TCPS (no capture-backed evidence for its shape;
unimplemented rather than guessed).
