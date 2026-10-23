// An explicit local snapshot of Oracle data: a DuckDB table filled from a query
// over attached Oracle tables, every Oracle table of that catalog read AS OF one
// change number, with where it came from kept in the table's own comment so it
// can be listed and refreshed. Nothing is hidden: the table is an ordinary
// DuckDB table the user can query, index, export or drop.

#include "oracle_adapter.hpp"

#include "duckdb.hpp"

#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/main/connection.hpp"

namespace duckdb {

namespace {

constexpr const char *SNAPSHOT_MARK = "oracle_snapshot\n";

struct SnapshotInfo {
    std::string schema;
    std::string name;
    std::string catalog;
    std::string scn;
    std::string taken_at;
    std::string source;
    int64_t rows = 0;
};

struct SnapshotGlobalState final : GlobalTableFunctionState {
    std::vector<SnapshotInfo> rows;
    idx_t next = 0;
};

struct SnapshotBindData final : TableFunctionData {
    std::string catalog;
    std::string name;
    std::string source;
    bool refresh = false;
};

std::string QuotedName(const std::string &name) {
    return KeywordHelper::WriteQuotedAndEscaped(name, '"');
}

std::string Comment(const SnapshotInfo &info) {
    return std::string(SNAPSHOT_MARK) + "catalog=" + info.catalog + "\nscn=" + info.scn + "\ntaken_at=" + info.taken_at +
           "\nsource=" + info.source;
}

bool ParseComment(const std::string &comment, SnapshotInfo &info) {
    if (comment.compare(0, std::string(SNAPSHOT_MARK).size(), SNAPSHOT_MARK) != 0) {
        return false;
    }
    size_t position = std::string(SNAPSHOT_MARK).size();
    const auto field = [&](const std::string &key, std::string &value, bool last) {
        if (comment.compare(position, key.size() + 1, key + "=") != 0) {
            return false;
        }
        position += key.size() + 1;
        const auto end = last ? std::string::npos : comment.find('\n', position);
        value = comment.substr(position, end == std::string::npos ? std::string::npos : end - position);
        position = end == std::string::npos ? comment.size() : end + 1;
        return true;
    };
    return field("catalog", info.catalog, false) && field("scn", info.scn, false) &&
           field("taken_at", info.taken_at, false) && field("source", info.source, true);
}

std::string Literal(const std::string &text) {
    return KeywordHelper::WriteQuotedAndEscaped(text, '\'');
}

// DuckDB 2.0 hands back a result read chunk by chunk; this reads it all.
struct Rows {
    std::string error;
    std::vector<std::vector<Value>> values;
    bool HasError() const {
        return !error.empty();
    }
    idx_t RowCount() const {
        return values.size();
    }
    Value GetValue(idx_t column, idx_t row) const {
        return values.at(row).at(column);
    }
};

Rows Run(Connection &connection, const std::string &sql) {
    Rows rows;
    auto result = connection.Query(sql);
    if (result->HasError()) {
        rows.error = result->GetError();
        return rows;
    }
    try {
        const auto columns = result->ColumnCount();
        while (auto chunk = result->Fetch()) {
            if (chunk->size() == 0) {
                break;
            }
            for (idx_t row = 0; row < chunk->size(); row++) {
                std::vector<Value> line;
                for (idx_t column = 0; column < columns; column++) {
                    line.push_back(chunk->GetValue(column, row));
                }
                rows.values.push_back(std::move(line));
            }
        }
    } catch (const std::exception &error) {
        rows.error = error.what();
    }
    return rows;
}

void Require(const Rows &result, const std::string &what) {
    if (result.HasError()) {
        throw IOException("%s: %s", what, result.error);
    }
}

// Builds the snapshot on a connection of its own, so the statement that asked for
// it is not part of the transaction that writes the table.
SnapshotInfo CreateSnapshot(ClientContext &context, const std::string &catalog, const std::string &display_name,
                            const std::string &qualified_name, const std::string &source) {
    if (qualified_name.empty()) {
        throw InvalidInputException("oracle_snapshot needs a table name");
    }
    const auto scn = OracleCurrentScn(context, catalog);
    SnapshotInfo info;
    info.catalog = catalog;
    info.name = display_name;
    info.scn = scn;
    info.source = source;
    info.taken_at = Timestamp::ToString(Timestamp::GetCurrentTimestamp());
    Connection connection(*context.db);
    OraclePinSnapshot(*connection.context, catalog, scn);
    Require(Run(connection, "CREATE OR REPLACE TABLE " + qualified_name + " AS " + source),
            "oracle_snapshot could not build " + display_name);
    auto counted = Run(connection, "SELECT count(*) FROM " + qualified_name);
    if (counted.HasError() || counted.RowCount() != 1) {
        throw IOException("oracle_snapshot could not count %s", display_name);
    }
    info.rows = counted.GetValue(0, 0).GetValue<int64_t>();
    Require(Run(connection, "COMMENT ON TABLE " + qualified_name + " IS " + Literal(Comment(info))),
            "oracle_snapshot could not record where " + display_name + " came from");
    return info;
}

std::vector<SnapshotInfo> ListSnapshots(ClientContext &context) {
    Connection connection(*context.db);
    auto result = Run(connection, "SELECT schema_name, table_name, comment, estimated_size FROM duckdb_tables() "
                                   "WHERE comment LIKE 'oracle_snapshot%' ORDER BY schema_name, table_name");
    if (result.HasError()) {
        throw IOException("oracle_snapshots could not list tables: %s", result.error);
    }
    std::vector<SnapshotInfo> infos;
    for (idx_t row = 0; row < result.RowCount(); row++) {
        SnapshotInfo info;
        if (!ParseComment(result.GetValue(2, row).ToString(), info)) {
            continue;
        }
        info.schema = result.GetValue(0, row).ToString();
        info.name = result.GetValue(1, row).ToString();
        info.rows = result.GetValue(3, row).IsNull() ? 0 : result.GetValue(3, row).GetValue<int64_t>();
        infos.push_back(std::move(info));
    }
    return infos;
}

unique_ptr<FunctionData> SnapshotBind(ClientContext &, TableFunctionBindInput &input, vector<LogicalType> &return_types,
                                      vector<Identifier> &names) {
    auto result = make_uniq<SnapshotBindData>();
    for (const auto &value : input.inputs) {
        if (value.IsNull()) {
            throw BinderException("oracle_snapshot arguments cannot be NULL");
        }
    }
    if (input.inputs.size() == 3) {
        result->catalog = input.inputs[0].GetValue<std::string>();
        result->name = input.inputs[1].GetValue<std::string>();
        result->source = input.inputs[2].GetValue<std::string>();
    } else {
        result->name = input.inputs[0].GetValue<std::string>();
        result->refresh = true;
    }
    names = {"table_name", "row_count", "scn", "taken_at"};
    return_types = {LogicalType::VARCHAR, LogicalType::BIGINT, LogicalType::VARCHAR, LogicalType::TIMESTAMP};
    return std::move(result);
}

unique_ptr<GlobalTableFunctionState> SnapshotInit(ClientContext &context, TableFunctionInitInput &input) {
    const auto &bind = input.bind_data->Cast<SnapshotBindData>();
    auto state = make_uniq<SnapshotGlobalState>();
    if (!bind.refresh) {
        state->rows.push_back(CreateSnapshot(context, bind.catalog, bind.name, QuotedName(bind.name), bind.source));
        return std::move(state);
    }
    for (const auto &info : ListSnapshots(context)) {
        if (info.name == bind.name) {
            state->rows.push_back(CreateSnapshot(context, info.catalog, info.name,
                                                 QuotedName(info.schema) + "." + QuotedName(info.name), info.source));
            return std::move(state);
        }
    }
    throw InvalidInputException("'%s' is not a table made by oracle_snapshot", bind.name);
}

unique_ptr<GlobalTableFunctionState> SnapshotListInit(ClientContext &context, TableFunctionInitInput &) {
    auto state = make_uniq<SnapshotGlobalState>();
    state->rows = ListSnapshots(context);
    return std::move(state);
}

unique_ptr<FunctionData> SnapshotListBind(ClientContext &, TableFunctionBindInput &, vector<LogicalType> &return_types,
                                          vector<Identifier> &names) {
    names = {"schema_name", "table_name", "catalog", "scn", "taken_at", "row_count", "source"};
    return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
                    LogicalType::TIMESTAMP, LogicalType::BIGINT, LogicalType::VARCHAR};
    return make_uniq<TableFunctionData>();
}

void SnapshotFunction(ClientContext &, TableFunctionInput &input, DataChunk &output) {
    auto &state = input.global_state->Cast<SnapshotGlobalState>();
    idx_t count = 0;
    const auto columns = output.ColumnCount();
    while (state.next < state.rows.size() && count < STANDARD_VECTOR_SIZE) {
        const auto &row = state.rows[state.next++];
        const auto taken = Timestamp::FromString(row.taken_at, false);
        if (columns == 4) {
            output.data[0].SetValue(count, Value(row.name));
            output.data[1].SetValue(count, Value::BIGINT(row.rows));
            output.data[2].SetValue(count, Value(row.scn));
            output.data[3].SetValue(count, Value::TIMESTAMP(taken));
        } else {
            output.data[0].SetValue(count, Value(row.schema));
            output.data[1].SetValue(count, Value(row.name));
            output.data[2].SetValue(count, Value(row.catalog));
            output.data[3].SetValue(count, Value(row.scn));
            output.data[4].SetValue(count, Value::TIMESTAMP(taken));
            output.data[5].SetValue(count, Value::BIGINT(row.rows));
            output.data[6].SetValue(count, Value(row.source));
        }
        count++;
    }
    output.SetChildCardinality(count);
}

} // namespace

vector<CreateTableFunctionInfo> OracleSnapshotFunctionInfos() {
    vector<CreateTableFunctionInfo> infos;
    TableFunction make("oracle_snapshot", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
                       SnapshotFunction, SnapshotBind, SnapshotInit);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(make),
        {{"catalog_name", "table_name", "source_sql"},
         "Builds a local DuckDB table from a query over attached Oracle tables, reading every table of that catalog "
         "AS OF one SCN, and records the SCN and the query in the table's comment so it can be listed and refreshed.",
         "SELECT * FROM oracle_snapshot('ora', 'departments_snapshot', "
         "'SELECT * FROM ora.main.QUACK_DEMO_DEPARTMENTS WHERE department_id > 10');",
         {"oracle", "snapshot"}}));
    TableFunction refresh("oracle_snapshot_refresh", {LogicalType::VARCHAR}, SnapshotFunction, SnapshotBind, SnapshotInit);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(refresh),
        {{"table_name"},
         "Runs the query of a table made by oracle_snapshot again, at a new SCN, and replaces its rows.",
         "SELECT * FROM oracle_snapshot_refresh('departments_snapshot');", {"oracle", "snapshot"}}));
    TableFunction list("oracle_snapshots", {}, SnapshotFunction, SnapshotListBind, SnapshotListInit);
    infos.push_back(DocumentedTableFunctionInfo(
        std::move(list),
        {{},
         "Lists the local tables made by oracle_snapshot: the catalog, the SCN, when it was taken, the row count and the query.",
         "SELECT * FROM oracle_snapshots();", {"oracle", "snapshot"}}));
    return infos;
}

void RegisterOracleSnapshot(ExtensionLoader &loader) {
    for (auto &info : OracleSnapshotFunctionInfos()) {
        loader.RegisterFunction(std::move(info));
    }
}

} // namespace duckdb
