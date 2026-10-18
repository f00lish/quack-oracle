#pragma once

// DuckDB 2.0 has no MaterializedQueryResult: a result is read chunk by chunk.
// The opt-in live tests check values by row and column, so this reads one
// whole result into memory first. Only the small results those tests ask for
// go through it.
#include "duckdb.hpp"

#include <string>
#include <vector>

class LiveQueryResult {
public:
    explicit LiveQueryResult(duckdb::unique_ptr<duckdb::QueryResult> result) {
        if (result->HasError()) {
            error = result->GetError();
            return;
        }
        try {
            while (auto chunk = result->Fetch()) {
                if (chunk->size() == 0) {
                    break;
                }
                for (duckdb::idx_t row = 0; row < chunk->size(); row++) {
                    std::vector<duckdb::Value> values;
                    for (duckdb::idx_t column = 0; column < chunk->ColumnCount(); column++) {
                        values.push_back(chunk->GetValue(column, row));
                    }
                    rows.push_back(std::move(values));
                }
            }
        } catch (const std::exception &exception) {
            // A failure while streaming is an error of this result, the same
            // as one reported before the first row.
            error = duckdb::ErrorData(exception).Message();
            rows.clear();
            return;
        }
        if (result->HasError()) {
            error = result->GetError();
            rows.clear();
        }
    }

    bool HasError() const {
        return !error.empty();
    }

    const std::string &GetError() const {
        return error;
    }

    duckdb::idx_t RowCount() const {
        return rows.size();
    }

    duckdb::Value GetValue(duckdb::idx_t column, duckdb::idx_t row) const {
        return rows.at(row).at(column);
    }

private:
    std::string error;
    std::vector<std::vector<duckdb::Value>> rows;
};
