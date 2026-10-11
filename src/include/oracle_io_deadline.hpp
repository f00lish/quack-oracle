#pragma once
#include "duckdb.hpp"
#include "oracle_scanner/io_deadline.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_context_state.hpp"
namespace duckdb {
// Internal backend seam. Each private DuckDB metadata/receipt connection has
// its own source, bound into configs before ATTACH opens its first session.
class OracleIoDeadlineState final : public ClientContextState {
public:
    std::shared_ptr<oracle_scanner::OracleIoDeadline> source = std::make_shared<oracle_scanner::OracleIoDeadline>();
};
// Header-defined seam: the backend does not link a second scanner into its
// artifact. Both use the same named connection-local registered state.
inline std::shared_ptr<oracle_scanner::OracleIoDeadline> OracleIoDeadlineFor(ClientContext &context) {
    return context.registered_state->GetOrCreate<OracleIoDeadlineState>("oracle_scanner.io_deadline")->source;
}
}
