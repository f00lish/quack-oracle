# oracle_scanner 0.6.0

Built for DuckDB v2.0.0. Install with `INSTALL oracle_scanner FROM community;`
once the release is published. Everything below is in addition to 0.5.1; nothing
from 0.5.1 was removed. The reference for each item is the README section named in
brackets, and the settings table is in [CAPABILITIES.md](CAPABILITIES.md).

## Connecting

- Easy Connect strings, `DSN`, `CONFIG_DIR`, wallet folders and `TNS_ADMIN` lookup
  of an alias; `SID` as well as a service name; a `DESCRIPTION_LIST` that names one
  database is read as its addresses (one that names different databases is refused).
  [Connect to a database]
- `MODULE`, `ACTION`, `CLIENT_IDENTIFIER` and `CLIENT_INFO` in the secret are sent to
  Oracle and show in `V$SESSION`.
- `ATTACH ... (SCHEMA 'owner')` reads another user's tables; an attached table is
  found whatever case its name is typed in.

## Types

- Read: `NCHAR`, `NVARCHAR2`, `INTERVAL`, `ROWID`, `UROWID`, `LONG`, `LONG RAW`,
  `BOOLEAN`, `TIMESTAMP WITH LOCAL TIME ZONE`, `JSON` (decoded from OSON), `VECTOR`,
  and `XMLTYPE` as text. `NUMBER(p,-s)` and `NUMBER(p,s>p)` are mapped exactly;
  `oracle_unconstrained_number` chooses what a `NUMBER` with no declared precision
  becomes. [Which Oracle types work]
- Write: national text, intervals, `BOOLEAN`, local-zone times, `CLOB`/`NCLOB`/`BLOB`
  (past 8 MiB through temporary LOBs, up to 1 GiB), `JSON`, `VECTOR`, `XMLTYPE`.
  Every writable type is also accepted as a query parameter and as an argument of
  `oracle_call_auto` / `oracle_call_named`.

## Statements and functions

- `UPDATE` and `DELETE ... RETURNING` on an attached table.
- `oracle_plsql` and `oracle_plsql_transaction`: anonymous PL/SQL blocks.
- `oracle_vector_search`: the k nearest rows by `VECTOR_DISTANCE`, ranked by Oracle.
- `oracle_snapshot`, `oracle_snapshot_refresh`, `oracle_snapshots`: a local DuckDB
  table built from a query over attached tables, read `AS OF` one SCN, with its
  source recorded in the table's comment.

## Less data moved

Each of these applies only where Oracle's answer is provably what DuckDB's would be;
anything else stays in DuckDB, as before. Each has a setting to turn it off.
[Pushing filters down to Oracle]

- Filters Oracle cannot be sent are applied inside the scan, so filter pushdown is on
  by default (`oracle_filter_pushdown`).
- Row count and distinct counts from Oracle's statistics reach the optimizer; a join's
  keys reach the scan as `IN` lists (over 1000 values as several lists, up to 16384).
- `TABLESAMPLE SYSTEM` is taken by Oracle.
- `ORDER BY ... LIMIT` is ranked by Oracle (`oracle_top_n_pushdown`).
- `COUNT`, `SUM`, `MIN`, `MAX` and `GROUP BY` are computed by Oracle
  (`oracle_aggregate_pushdown`).
- An inner join of two attached tables of one database is one statement
  (`oracle_join_pushdown`).
- Tests of a path in a native `JSON` column are narrowed with `JSON_VALUE` /
  `JSON_EXISTS`; DuckDB still applies its own test.
- When DuckDB applies a filter itself, `CLOB`/`BLOB`/`JSON`/`VECTOR`/`XMLTYPE` columns
  the filter does not read are fetched afterwards, only for the rows that passed
  (`oracle_deferred_columns`).

## Faster and more consistent reads

- `oracle_parallel_scan` reads a big table through several sessions in ROWID ranges at
  one SCN. It now defaults to `-1`: automatic, as many sessions as DuckDB has threads
  (at most 8) for a table whose statistics say 500,000 rows or more.
  [Read a big table faster]
- `oracle_consistent_read` (off by default) reads every attached table of a statement
  at one SCN.
- Fixes in `oracle_scan_parallel` shard boundaries.
- `EXPLAIN ANALYZE` shows the statement sent, rows returned, sessions, network bytes and
  round trips, fetch and conversion time, and the filters DuckDB applied afterwards.

## Behaviour changes to be aware of

- `oracle_filter_pushdown` is on by default; a filter that cannot be translated is no
  longer refused but applied by the scan.
- `oracle_parallel_scan` defaults to automatic. Set it to `0` for the old one-session
  behaviour. A user without `DBA_EXTENTS` is read with one session either way.
- A scan of a table with a pushed-down aggregate, join, Top-N or deferred columns
  sends different statements than 0.5.1; `EXPLAIN ANALYZE` shows exactly which.

## Verified, and not

Verified against live Oracle 19c and Oracle Free 23ai (the live stages, the new-types
stage, and hand checks listed in the README sections); every pushdown was also
compared row for row with the pushdown switched off on both. The protocol and adapter
suites run under ASan and UBSan.

Not re-run for this release: OCI Autonomous Database / TCPS, servers other than 19c and
23ai (TTC field versions 18 to 23 are not all covered), the Windows view check script, and
a `VECTOR` HNSW index (IVF was checked). `JSON` path narrowing needs Oracle 21c or later
for the native type. Known limits: temporary-LOB writes stop at 1 GiB; `RETURNING` refuses
tables with LOB, JSON or VECTOR columns; an `IN` list over a JSON path is not narrowed.
