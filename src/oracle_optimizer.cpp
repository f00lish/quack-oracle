// Plan rewrites for an attached Oracle table, run after DuckDB's own optimizers.
//
// Top-N. `SELECT ... FROM o.T ORDER BY k LIMIT n` plans as a TOP_N over the
// scan, and the scan reads the whole table. When every sort key is a column the
// scan reads and Oracle orders it exactly as DuckDB does, the scan can ask for
// `ORDER BY k FETCH FIRST n ROWS ONLY` and read n rows. The TOP_N stays in the
// plan, which is what keeps this safe: DuckDB sorts what comes back and keeps the
// first n again, so Oracle only has to return rows that include the true first
// n, and ties at the boundary are the ties any ORDER BY ... LIMIT leaves open.
//
// What "orders it exactly as DuckDB does" is limited on purpose: numbers, dates
// and timestamps, where both engines compare values; and NULL placement is
// always spelled out. Text sorts by the session's collation in Oracle and by
// bytes in DuckDB, so a text key is left alone.

#include "oracle_adapter.hpp"

#include "duckdb/main/config.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/operator/logical_projection.hpp"
#include "duckdb/planner/operator/logical_top_n.hpp"

namespace duckdb {

namespace {

// Rows past this are not worth asking Oracle to rank for: the statement says how
// many rows to return, and a client-side heap of that size is no longer cheap.
constexpr idx_t MAX_PUSHED_TOP_N = 100000;

bool OrderableInOracle(const OracleColumn &column) {
	switch (MappedType(column).id()) {
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::DECIMAL:
	case LogicalTypeId::TIMESTAMP:
	case LogicalTypeId::TIMESTAMP_NS:
	case LogicalTypeId::TIMESTAMP_TZ:
		return true;
	default:
		return false;
	}
}

// Follows a column binding down through projections that pass columns on
// unchanged, to a column of the scan. Anything else on the way, such as a
// computed column, is not something Oracle could be asked to sort by.
bool ResolveToScanColumn(const vector<LogicalProjection *> &projections, const LogicalGet &get, ColumnBinding binding,
                         column_t &column) {
	for (const auto *projection : projections) {
		if (binding.table_index != projection->table_index) {
			return false;
		}
		const auto &expression = projection->GetExpression(binding);
		if (expression.GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return false;
		}
		binding = expression.Cast<BoundColumnRefExpression>().Binding();
	}
	if (binding.table_index != get.table_index) {
		return false;
	}
	const auto &column_ids = get.GetColumnIds();
	const auto position = binding.column_index.GetIndex();
	if (position >= column_ids.size() || column_ids[position].HasChildren()) {
		return false;
	}
	column = column_ids[position].GetPrimaryIndex();
	return true;
}

void PushTopN(ClientContext &context, LogicalTopN &top) {
	Value enabled;
	if (context.TryGetCurrentSetting("oracle_top_n_pushdown", enabled) && !enabled.IsNull() && !BooleanValue::Get(enabled)) {
		return;
	}
	if (top.limit > MAX_PUSHED_TOP_N || top.offset > MAX_PUSHED_TOP_N) {
		return;
	}
	vector<LogicalProjection *> projections;
	auto *node = top.children[0].get();
	while (node->type == LogicalOperatorType::LOGICAL_PROJECTION) {
		projections.push_back(&node->Cast<LogicalProjection>());
		node = node->children[0].get();
	}
	if (node->type != LogicalOperatorType::LOGICAL_GET) {
		return;
	}
	auto &get = node->Cast<LogicalGet>();
	auto *bind = get.bind_data ? dynamic_cast<OracleQueryBindData *>(get.bind_data.get()) : nullptr;
	if (!bind || !bind->deferred_scan) {
		return;
	}
	vector<OracleTopNKey> keys;
	for (const auto &order : top.orders) {
		if (order.expression->GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return;
		}
		if (order.null_order != OrderByNullType::NULLS_FIRST && order.null_order != OrderByNullType::NULLS_LAST) {
			return;
		}
		column_t column;
		if (!ResolveToScanColumn(projections, get, order.expression->Cast<BoundColumnRefExpression>().Binding(), column) ||
		    column >= bind->columns.size() || !OrderableInOracle(bind->columns[column])) {
			return;
		}
		keys.push_back({column, order.type == OrderType::DESCENDING, order.null_order == OrderByNullType::NULLS_FIRST});
	}
	if (keys.empty()) {
		return;
	}
	bind->top_n = std::move(keys);
	bind->top_n_rows = top.limit + top.offset;
}

void Walk(ClientContext &context, LogicalOperator &op) {
	if (op.type == LogicalOperatorType::LOGICAL_TOP_N) {
		PushTopN(context, op.Cast<LogicalTopN>());
	}
	for (auto &child : op.children) {
		Walk(context, *child);
	}
}

void OptimizeOraclePlan(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
	if (plan) {
		Walk(input.context, *plan);
	}
}

} // namespace

void RegisterOracleOptimizer(DatabaseInstance &db) {
	OptimizerExtension extension;
	extension.optimize_function = OptimizeOraclePlan;
	OptimizerExtension::Register(DBConfig::GetConfig(db), std::move(extension));
	DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_top_n_pushdown",
	    "Let Oracle rank and cut an ORDER BY ... LIMIT over an attached table (numbers, dates and timestamps) so only "
	    "the first rows are read. DuckDB still sorts what comes back.",
	    LogicalType::BOOLEAN, Value::BOOLEAN(true));
}

// The ORDER BY ... FETCH FIRST clause for a pushed Top-N, or empty when the keys
// were not pushable after all (see OracleQueryInit).
std::string OracleTopNClause(const OracleQueryBindData &bind) {
	if (bind.top_n.empty()) {
		return std::string();
	}
	std::string clause = " ORDER BY ";
	for (size_t index = 0; index < bind.top_n.size(); index++) {
		const auto &key = bind.top_n[index];
		if (index > 0) {
			clause += ", ";
		}
		clause += KeywordHelper::WriteQuotedAndEscaped(bind.columns[key.column].name, '"');
		clause += key.descending ? " DESC" : " ASC";
		clause += key.nulls_first ? " NULLS FIRST" : " NULLS LAST";
	}
	return clause + " FETCH FIRST " + std::to_string(bind.top_n_rows) + " ROWS ONLY";
}

} // namespace duckdb
