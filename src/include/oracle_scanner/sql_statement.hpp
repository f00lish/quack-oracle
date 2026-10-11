#pragma once

#include "oracle_scanner/sql_binds.hpp"

namespace oracle_scanner {

enum class OracleSqlKind { QUERY, DML, PLSQL, DDL_OR_OTHER, ADMIN };

OracleSqlKind ClassifyOracleSql(const std::string &sql);
void ValidateOracleQuery(const std::string &sql, const std::vector<OracleBind> &binds);
void ValidateOracleDml(const std::string &sql, const std::vector<OracleBind> &binds);
void ValidateOracleAdmin(const std::string &sql);

} // namespace oracle_scanner
