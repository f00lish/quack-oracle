#define DUCKDB_EXTENSION_MAIN

#include "oracle_scanner_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

namespace duckdb {

void RegisterOracleScannerVersion(ExtensionLoader &loader);
void RegisterOracleSecrets(ExtensionLoader &loader);
void RegisterOracleQuery(ExtensionLoader &loader);
void RegisterOracleAttachedCatalog(ExtensionLoader &loader);
void RegisterOracleSessionPool(ExtensionLoader &loader);
void RegisterOracleParallelScan(ExtensionLoader &loader);

// Supplied by CMake from EXTENSION_VERSION in extension_config.cmake, so this
// answer cannot drift from the version the artifact is stamped with. The
// fallback only ever applies to a build that bypasses this project's CMake.
#ifndef ORACLE_SCANNER_VERSION_STRING
#define ORACLE_SCANNER_VERSION_STRING "0.0.0-unknown"
#endif

static void OracleScannerVersion(DataChunk &args, ExpressionState &, Vector &result) {
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::SetNull(result, false);
	ConstantVector::GetData<string_t>(result)[0] =
	    StringVector::AddString(result, ORACLE_SCANNER_VERSION_STRING);
}

CreateScalarFunctionInfo OracleScannerVersionFunctionInfo() {
	CreateScalarFunctionInfo info(ScalarFunction("oracle_scanner_version", {}, LogicalType::VARCHAR, OracleScannerVersion));
	// What the bare RegisterFunction(ScalarFunction) overload sets.
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	FunctionDescription description;
	description.description = "Returns the version of this oracle_scanner build.";
	description.examples = {"oracle_scanner_version()"};
	description.categories = {"oracle", "metadata"};
	info.descriptions.push_back(std::move(description));
	return info;
}

void RegisterOracleScannerVersion(ExtensionLoader &loader) {
	loader.RegisterFunction(OracleScannerVersionFunctionInfo());
}

static void OracleIoDeadlineVersion(DataChunk &, ExpressionState &, Vector &result) {
	result.SetVectorType(VectorType::CONSTANT_VECTOR);
	ConstantVector::SetNull(result, false);
	ConstantVector::GetData<uint64_t>(result)[0] = 1;
}

// A companion extension that shares this scanner's per-connection IO deadline
// (oracle_io_deadline.hpp) asks for this number before relying on it. It names
// the version of that contract, not of the extension.
CreateScalarFunctionInfo OracleIoDeadlineVersionFunctionInfo() {
	CreateScalarFunctionInfo info(
	    ScalarFunction("oracle_scanner_io_deadline_version", {}, LogicalType::UBIGINT, OracleIoDeadlineVersion));
	info.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
	FunctionDescription description;
	description.description =
	    "Returns the version of the IO deadline contract this build offers to companion extensions.";
	description.examples = {"oracle_scanner_io_deadline_version()"};
	description.categories = {"oracle", "metadata"};
	info.descriptions.push_back(std::move(description));
	return info;
}

static void LoadInternal(ExtensionLoader &loader) {
	loader.SetDescription("Native Oracle TNS/TTC connectivity for DuckDB");
	RegisterOracleScannerVersion(loader);
	loader.RegisterFunction(OracleIoDeadlineVersionFunctionInfo());
	RegisterOracleSecrets(loader);
	RegisterOracleQuery(loader);
	RegisterOracleAttachedCatalog(loader);
	RegisterOracleSessionPool(loader);
	RegisterOracleParallelScan(loader);
}

void OracleScannerExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string OracleScannerExtension::Name() {
	return "oracle_scanner";
}

std::string OracleScannerExtension::Version() const {
#ifdef EXT_VERSION_ORACLE_SCANNER
	return EXT_VERSION_ORACLE_SCANNER;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(oracle_scanner, loader) {
	duckdb::LoadInternal(loader);
}
}
