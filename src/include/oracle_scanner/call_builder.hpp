#pragma once

#include "oracle_scanner/session.hpp"

#include <string>
#include <vector>

namespace oracle_scanner {

// Validates a schema[.package].procedure name without changing its case or
// quote semantics. Database links and arbitrary SQL expressions are excluded.
std::string ParseOracleCallableName(const std::string &value);

// The same name split into the components the data dictionary stores: an
// unquoted identifier folded to upper case, a quoted one kept as its text with
// doubled quotes collapsed. One to three components, validated exactly as
// ParseOracleCallableName validates them.
std::vector<std::string> SplitOracleCallableName(const std::string &value);

// Produces an anonymous PL/SQL procedure block. Argument names are used both
// as named PL/SQL arguments and as bind placeholders, so they are strictly
// validated and case-insensitively unique.
std::string BuildOracleProcedureCallBlock(const std::string &qualified_name,
                                          const std::vector<OracleBind> &arguments);

// Produces an anonymous PL/SQL function block. The return bind must be OUT or
// IN OUT and must not collide with a named function argument.
std::string BuildOracleFunctionCallBlock(const std::string &qualified_name, const OracleBind &return_bind,
                                         const std::vector<OracleBind> &arguments);

// The bounds of a DML_COMPOSITE request. They are checked here, before any
// wire work, and the adapter reports them by these names.
constexpr size_t ORACLE_DML_COMPOSITE_MAX_OPERATIONS = 16;
constexpr size_t ORACLE_DML_COMPOSITE_MAX_BINDS = 256;
constexpr size_t ORACLE_DML_COMPOSITE_MAX_SQL_BYTES = 64U * 1024U;
constexpr size_t ORACLE_DML_COMPOSITE_MAX_PAYLOAD_BYTES = 8U * 1024U * 1024U;
constexpr uint64_t ORACLE_DML_COMPOSITE_MAX_EXPECTED_ROWS = 1000000;

// The Oracle error a DML_COMPOSITE block raises when a statement's
// SQL%ROWCOUNT differs from the count it was given.
constexpr int32_t ORACLE_DML_COMPOSITE_ROW_COUNT_ERROR = -20906;

// Produces the anonymous block of a DML_COMPOSITE request: each statement in
// order, each followed by a check that raises unless SQL%ROWCOUNT is exactly
// what was expected. The statements are validated as oracle_execute validates
// one; every bind is used and every placeholder is bound. The block itself
// never commits or rolls back.
std::string BuildOracleDmlCompositeBlock(const std::vector<OracleDmlOperation> &operations,
                                         const std::vector<OracleBind> &arguments);

std::string BuildOracleCallBlock(const OracleCallRequest &request);

} // namespace oracle_scanner
