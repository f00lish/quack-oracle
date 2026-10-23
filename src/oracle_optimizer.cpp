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
#include "duckdb/optimizer/column_binding_replacer.hpp"
#include "duckdb/optimizer/optimizer_extension.hpp"
#include "duckdb/planner/expression/bound_aggregate_expression.hpp"
#include "duckdb/planner/expression/bound_cast_expression.hpp"
#include "duckdb/planner/operator/logical_aggregate.hpp"
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

// Aggregates. `SELECT g, count(*), sum(x) FROM o.T WHERE ... GROUP BY g` plans as
// an AGGREGATE over the scan, and the scan reads every row for DuckDB to add up.
// When the aggregate is one Oracle computes exactly as DuckDB does, the AGGREGATE
// and the scan are replaced by a scan of the statement
// `SELECT g, COUNT(*), SUM(x) FROM T WHERE ... GROUP BY g`, so the groups travel
// and not the rows.
//
// What counts as "exactly as DuckDB does" is narrow on purpose:
//  - COUNT(*), COUNT(column), SUM, MIN and MAX of a column, not DISTINCT, with no
//    FILTER or ORDER BY; no GROUPING SETS or GROUPING();
//  - SUM only of an exact number (integer or fixed-scale decimal), whose result
//    type matches DuckDB's; MIN and MAX and the group keys only of numbers, dates
//    and timestamps, which compare the same in both engines. Text is left out:
//    Oracle may group and order it by a collation (NLS_COMP, blank-padded CHAR)
//    where DuckDB compares bytes; floating point is left out because the order of
//    addition changes the result;
//  - every filter was translated into the WHERE clause, none is left for DuckDB
//    to apply to the rows (it would then see groups instead of rows), and the
//    scan has no sample and no filter a join will add later.
// Anything else leaves the plan as it was.

struct PushedAggregate {
	std::string sql;
	std::vector<OracleColumn> columns;
	vector<LogicalType> types;      // what the scan returns
	vector<LogicalType> wanted;     // what the AGGREGATE returned, groups first
};

bool KeyType(const LogicalType &type) {
	switch (type.id()) {
	case LogicalTypeId::BIGINT:
	case LogicalTypeId::DECIMAL:
	case LogicalTypeId::TIMESTAMP:
	case LogicalTypeId::TIMESTAMP_NS:
		return true;
	default:
		return false;
	}
}

std::string Quoted(const OracleColumn &column) {
	return KeywordHelper::WriteQuotedAndEscaped(column.name, '"');
}

bool PlanPushedAggregate(ClientContext &context, LogicalAggregate &aggregate, LogicalGet &get,
                         const vector<LogicalProjection *> &projections, OracleQueryBindData &bind,
                         PushedAggregate &result) {
	if (!aggregate.grouping_functions.empty() || aggregate.grouping_sets.size() > 1 ||
	    (aggregate.grouping_sets.size() == 1 && aggregate.grouping_sets[0].size() != aggregate.groups.size()) ||
	    get.extra_info.sample_options || (get.dynamic_filters && get.dynamic_filters->HasFilters())) {
		return false;
	}
	const auto &column_ids = get.GetColumnIds();
	std::vector<column_t> scanned;
	for (const auto &id : column_ids) {
		if (id.HasChildren()) {
			return false;
		}
		scanned.push_back(id.GetPrimaryIndex());
	}
	std::string where;
	if (get.table_filters.HasFilters() || get.table_filters.HasMultiColumnFilters()) {
		try {
			auto split = SplitOracleFilters(get.table_filters, bind.columns, scanned);
			if (!split.local.empty()) {
				return false;
			}
			where = std::move(split.where);
		} catch (const std::exception &) {
			return false;
		}
	}
	const auto resolve = [&](const Expression &expression, column_t &column) {
		if (expression.GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
			return false;
		}
		return ResolveToScanColumn(projections, get, expression.Cast<BoundColumnRefExpression>().Binding(), column) &&
		       column < bind.columns.size();
	};
	std::string select_list;
	std::string group_list;
	const auto add = [&](const std::string &expression, OracleColumn declared, const LogicalType &type,
	                     const LogicalType &wanted) {
		declared.name = "C" + std::to_string(result.columns.size());
		select_list += (select_list.empty() ? "" : ", ") + expression + " " + KeywordHelper::WriteQuotedAndEscaped(declared.name, '"');
		result.columns.push_back(std::move(declared));
		result.types.push_back(type);
		result.wanted.push_back(wanted);
	};
	for (const auto &group : aggregate.groups) {
		column_t column;
		if (!resolve(*group, column)) {
			return false;
		}
		const auto &source = bind.columns[column];
		const auto type = MappedType(source);
		if (!KeyType(type) || type != group->GetReturnType()) {
			return false;
		}
		add(Quoted(source), source, type, type);
		group_list += (group_list.empty() ? "" : ", ") + Quoted(source);
	}
	for (const auto &expression : aggregate.expressions) {
		if (expression->GetExpressionClass() != ExpressionClass::BOUND_AGGREGATE) {
			return false;
		}
		const auto &call = expression->Cast<BoundAggregateExpression>();
		if (call.IsDistinct() || call.GetFilter() || call.GetOrderBys() || call.GetChildren().size() > 1) {
			return false;
		}
		const auto name = StringUtil::Lower(call.Function().GetName().GetIdentifierName());
		const auto &wanted = call.GetReturnType();
		OracleColumn count_column;
		count_column.oracle_type = 2;
		count_column.precision = 18;
		count_column.scale = 0;
		count_column.nullable = false;
		if (name == "count_star" && call.GetChildren().empty()) {
			add("CAST(COUNT(*) AS NUMBER(18,0))", count_column, LogicalType::BIGINT, wanted);
			continue;
		}
		column_t column;
		if (call.GetChildren().size() != 1 || !resolve(*call.GetChildren()[0], column)) {
			return false;
		}
		const auto &source = bind.columns[column];
		const auto type = MappedType(source);
		if (name == "count" && wanted == LogicalType::BIGINT) {
			add("CAST(COUNT(" + Quoted(source) + ") AS NUMBER(18,0))", count_column, LogicalType::BIGINT, wanted);
		} else if ((name == "min" || name == "max") && KeyType(type) && wanted == type) {
			add(name == "min" ? "MIN(" + Quoted(source) + ")" : "MAX(" + Quoted(source) + ")", source, type, type);
		} else if (name == "sum" && source.oracle_type == 2 && source.precision >= 1 && source.scale >= 0 &&
		           source.scale <= source.precision && source.precision <= 38) {
			if (type.id() == LogicalTypeId::BIGINT && wanted == LogicalType::HUGEINT) {
				// A sum of integers can pass 18 digits, which no NUMBER this client maps to a
				// number can hold; Oracle spells it out and DuckDB reads it as a HUGEINT.
				OracleColumn text;
				add("TO_CHAR(SUM(" + Quoted(source) + "), 'TM9')", text, LogicalType::VARCHAR, wanted);
			} else if (type.id() == LogicalTypeId::DECIMAL && wanted == LogicalType::DECIMAL(38, source.scale)) {
				OracleColumn sum;
				sum.oracle_type = 2;
				sum.precision = 38;
				sum.scale = source.scale;
				add("CAST(SUM(" + Quoted(source) + ") AS NUMBER(38," + std::to_string(source.scale) + "))", sum, wanted,
				    wanted);
			} else {
				return false;
			}
		} else {
			return false;
		}
	}
	if (result.columns.empty()) {
		return false;
	}
	result.sql = "SELECT " + select_list + " FROM " + OracleObjectReference(bind.schema_name, bind.object_name);
	if (!where.empty()) {
		result.sql += " WHERE " + where;
	}
	if (!group_list.empty()) {
		result.sql += " GROUP BY " + group_list;
	}
	return true;
}

void PushAggregate(ClientContext &context, unique_ptr<LogicalOperator> &op, ColumnBindingReplacer &replacer) {
	auto &aggregate = op->Cast<LogicalAggregate>();
	vector<LogicalProjection *> projections;
	auto *node = aggregate.children[0].get();
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
	PushedAggregate pushed;
	if (!PlanPushedAggregate(context, aggregate, get, projections, *bind, pushed)) {
		return;
	}
	auto scan_bind = make_uniq<OracleQueryBindData>();
	scan_bind->aggregate_scan = true;
	scan_bind->aggregate_sql = std::move(pushed.sql);
	scan_bind->columns = std::move(pushed.columns);
	scan_bind->types = pushed.types;
	scan_bind->config = bind->config;
	scan_bind->password = bind->password;
	scan_bind->object_name = bind->object_name;
	scan_bind->schema_name = bind->schema_name;
	scan_bind->secret_name = bind->secret_name;
	scan_bind->catalog_name = bind->catalog_name;
	vector<Identifier> names;
	for (const auto &column : scan_bind->columns) {
		names.emplace_back(column.name);
	}
	BoundTableFunction function(get.function);
	function.filter_pushdown = false;
	function.projection_pushdown = false;
	function.sampling_pushdown = false;
	function.cardinality = nullptr;
	function.statistics = nullptr;
	function.get_table_entry = nullptr;
	const auto get_index = get.table_index;
	auto scan = make_uniq<LogicalGet>(get_index, std::move(function), std::move(scan_bind), pushed.types, names);
	vector<ColumnIndex> ids;
	for (idx_t index = 0; index < pushed.types.size(); index++) {
		ids.emplace_back(index);
	}
	scan->SetColumnIds(std::move(ids));
	// The AGGREGATE's own types, reached by a cast where the scan's differ (a sum
	// of integers arrives as text and is a HUGEINT here).
	vector<unique_ptr<Expression>> select;
	for (idx_t index = 0; index < pushed.types.size(); index++) {
		unique_ptr<Expression> reference =
		    make_uniq<BoundColumnRefExpression>(pushed.types[index], ColumnBinding(get_index, ProjectionIndex(index)));
		if (pushed.types[index] != pushed.wanted[index]) {
			reference = BoundCastExpression::AddCastToType(context, std::move(reference), pushed.wanted[index]);
		}
		select.push_back(std::move(reference));
	}
	const auto groups = aggregate.groups.size();
	const auto group_index = aggregate.group_index;
	const auto aggregate_index = aggregate.aggregate_index;
	const auto aggregates = aggregate.expressions.size();
	const auto estimate = aggregate.has_estimated_cardinality ? aggregate.estimated_cardinality : 1;
	auto projection = make_uniq<LogicalProjection>(group_index, std::move(select));
	projection->children.push_back(std::move(scan));
	projection->SetEstimatedCardinality(estimate);
	op = std::move(projection);
	// Whatever read the aggregates by (aggregate_index, n) now reads them from the projection.
	for (idx_t index = 0; index < aggregates; index++) {
		replacer.replacement_bindings.emplace_back(ColumnBinding(aggregate_index, ProjectionIndex(index)),
		                                           ColumnBinding(group_index, ProjectionIndex(groups + index)));
	}
}

void Walk(ClientContext &context, unique_ptr<LogicalOperator> &op, ColumnBindingReplacer &replacer, bool aggregates) {
	if (op->type == LogicalOperatorType::LOGICAL_TOP_N) {
		PushTopN(context, op->Cast<LogicalTopN>());
	}
	for (auto &child : op->children) {
		Walk(context, child, replacer, aggregates);
	}
	if (aggregates && op->type == LogicalOperatorType::LOGICAL_AGGREGATE_AND_GROUP_BY) {
		PushAggregate(context, op, replacer);
	}
}

void OptimizeOraclePlan(OptimizerExtensionInput &input, unique_ptr<LogicalOperator> &plan) {
	if (!plan) {
		return;
	}
	Value enabled;
	const auto aggregates = !input.context.TryGetCurrentSetting("oracle_aggregate_pushdown", enabled) || enabled.IsNull() ||
	                        BooleanValue::Get(enabled);
	ColumnBindingReplacer replacer;
	Walk(input.context, plan, replacer, aggregates);
	if (!replacer.replacement_bindings.empty()) {
		replacer.VisitOperator(*plan);
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
	DBConfig::GetConfig(db).AddExtensionOption(
	    "oracle_aggregate_pushdown",
	    "Let Oracle compute COUNT, SUM, MIN, MAX and GROUP BY over an attached table (numbers, dates and timestamps) "
	    "so the groups travel and not the rows.",
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
