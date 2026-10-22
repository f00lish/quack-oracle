// Opt-in live checks of the column types added in 0.6.0: NCHAR and NVARCHAR2,
// INTERVAL YEAR TO MONTH and DAY TO SECOND, ROWID and UROWID, LONG and LONG RAW.
//
// ORA19C_HOST, ORA19C_PORT, ORA19C_SERVICE, ORA19C_USER and ORA19C_PASSWORD
// name an administrative account. The test creates a throwaway user with a
// random password, writes the values with ordinary SQL, reads them back
// through oracle_query and through an attached catalog, and drops the user.
// Where Oracle can say what a value is — ROWIDTOCHAR, CAST(... AS VARCHAR2) —
// the comparison is against Oracle's own text rather than against a constant.
// Only stage names and Oracle error codes are printed.
#include "duckdb.hpp"
#include "oracle_scanner_extension.hpp"
#include "core_functions_extension.hpp"
#include "live_query_result.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>
#include <regex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace duckdb;

namespace {

std::string Env(const char *name) {
    const auto value = std::getenv(name);
    if (!value || !*value) {
        throw std::runtime_error(std::string("missing environment variable: ") + name);
    }
    return value;
}

std::string Literal(const std::string &value) {
    std::string result = "'";
    for (const auto c : value) {
        result += c == '\'' ? "''" : std::string(1, c);
    }
    return result + "'";
}

std::string Random(size_t length) {
    static const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    std::random_device device;
    std::uniform_int_distribution<size_t> pick(0, sizeof(alphabet) - 2);
    std::string result;
    for (size_t index = 0; index < length; index++) {
        result += alphabet[pick(device)];
    }
    return result;
}

[[noreturn]] void Fail(const std::string &stage, const std::string &error = std::string()) {
    std::smatch code;
    const std::regex ora("ORA-[0-9]{5}");
    std::cerr << "FAIL " << stage;
    if (std::regex_search(error, code, ora)) {
        std::cerr << " " << code.str();
    } else if (!error.empty()) {
        // Driver-side errors carry no SQL, binds or endpoints; keep their kind.
        const std::regex driver("TTC[^\\n]{0,120}");
        if (std::regex_search(error, code, driver)) {
            std::cerr << " " << code.str();
        }
    }
    std::cerr << "\n";
    throw std::runtime_error("live check failed");
}

void Check(bool condition, const std::string &stage) {
    if (!condition) {
        Fail(stage);
    }
}

unique_ptr<LiveQueryResult> Run(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = make_uniq<LiveQueryResult>(con.Query(sql));
    if (result->HasError()) {
        Fail(stage, result->GetError());
    }
    return result;
}

std::string Scalar(Connection &con, const std::string &sql, const std::string &stage) {
    auto result = Run(con, sql, stage);
    Check(result->RowCount() == 1, stage + ": one row");
    return result->GetValue(0, 0).ToString();
}

std::string Secret(const std::string &user, const std::string &password) {
    return "TYPE oracle, HOST " + Literal(Env("ORA19C_HOST")) + ", PORT " + Env("ORA19C_PORT") + ", SERVICE_NAME " +
           Literal(Env("ORA19C_SERVICE")) + ", USER " + Literal(user) + ", PASSWORD " + Literal(password) +
           ", CONNECT_TIMEOUT 5, READ_TIMEOUT 60";
}

std::string Admin(const std::string &statement) {
    std::string quoted;
    for (const auto c : statement) {
        quoted += c == '\'' ? "''" : std::string(1, c);
    }
    return "SELECT * FROM oracle_execute_admin('admin', '" + quoted + "');";
}

} // namespace

int main() {
    DuckDB db(nullptr);
    db.LoadStaticExtension<CoreFunctionsExtension>();
    db.LoadStaticExtension<OracleScannerExtension>();
    Connection admin(db);
    const auto user = "QO_TYPES_" + Random(8);
    const auto password = "P" + Random(20);
    bool created = false;
    int status = 0;
    const std::string emoji = "\xf0\x9f\x98\x80";
    try {
        Run(admin, "CREATE SECRET admin (" + Secret(Env("ORA19C_USER"), Env("ORA19C_PASSWORD")) + ");", "admin secret");
        Run(admin, Admin("CREATE USER " + user + " IDENTIFIED BY \"" + password + "\" QUOTA 64M ON USERS"), "create user");
        created = true;
        Run(admin, Admin("GRANT CREATE SESSION, CREATE TABLE TO " + user), "grant");
        const auto table = [&](const std::string &definition, const std::string &stage) {
            Run(admin, Admin("CREATE TABLE " + user + "." + definition), stage);
        };
        table("T_NATIONAL (ID NUMBER(5) PRIMARY KEY, NV NVARCHAR2(40), NC NCHAR(8))", "create national");
        table("T_INTERVAL (ID NUMBER(5) PRIMARY KEY, YM INTERVAL YEAR(4) TO MONTH, DS INTERVAL DAY(4) TO SECOND(6))",
              "create interval");
        table("T_ROWID (ID NUMBER(5) PRIMARY KEY, R ROWID, U UROWID(200))", "create rowid");
        table("T_LONG (ID NUMBER(5), L LONG)", "create long");
        table("T_LONG_RAW (ID NUMBER(5), L LONG RAW)", "create long raw");
        table("T_LONG_MID (A NUMBER(5), L LONG, B VARCHAR2(10))", "create long mid");
        table("T_IOT (K VARCHAR2(30) PRIMARY KEY, V NUMBER(5)) ORGANIZATION INDEX", "create iot");
        table("T_LOGICAL (ID NUMBER(5), U UROWID(4000))", "create logical");
        table("T_MIX (ID NUMBER(5), DOC CLOB, R ROWID)", "create mix");
        // Every table is created before the catalog is attached: it reads the
        // column dictionary once, and a table created after that is not in it.
        table("T_FINE (D INTERVAL DAY(2) TO SECOND(9))", "create fine");
        Run(admin, "CREATE SECRET rt (" + Secret(user, password) + ");", "runtime secret");
        Run(admin, "ATTACH 'rt' AS raw (TYPE oracle_scanner);", "attach");
        const auto dml = [&](const std::string &sql, const std::string &stage) {
            Run(admin, "SELECT * FROM oracle_execute_transaction('raw', " + Literal(sql) + ");", stage);
        };

        // NCHAR and NVARCHAR2: ASCII, Latin-1, Cyrillic, CJK, and a character
        // outside the BMP, which UTF-16 spends a surrogate pair on.
        dml("INSERT INTO T_NATIONAL VALUES (1, N'plain', N'ab')", "national 1");
        dml("INSERT INTO T_NATIONAL VALUES (2, N'h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji + "', N'\xe6\x97\xa5\xe6\x9c\xac')", "national 2");
        dml("INSERT INTO T_NATIONAL VALUES (3, NULL, NULL)", "national 3");
        dml("INSERT INTO T_NATIONAL VALUES (4, RPAD(N'\xd0\xb6', 40, N'\xd0\xb6'), N'12345678')", "national 4");
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, NV, NC FROM T_NATIONAL ORDER BY ID')"),
                                   std::string("raw.T_NATIONAL")}) {
            auto result = Run(admin, "SELECT id, nv, nc FROM " + source + " ORDER BY id;", "national read");
            Check(result->RowCount() == 4, "national rows");
            Check(result->GetValue(1, 0).ToString() == "plain" && result->GetValue(2, 0).ToString() == "ab      ",
                  "national ascii and blank padding");
            Check(result->GetValue(1, 1).ToString() == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82 " + emoji &&
                      result->GetValue(2, 1).ToString() == "\xe6\x97\xa5\xe6\x9c\xac      ",
                  "national multibyte and surrogate pair");
            Check(result->GetValue(1, 2).IsNull() && result->GetValue(2, 2).IsNull(), "national NULL");
            std::string forty;
            for (int i = 0; i < 40; i++) {
                forty += "\xd0\xb6";
            }
            Check(result->GetValue(1, 3).ToString() == forty && result->GetValue(2, 3).ToString() == "12345678",
                  "national at full width");
        }
        std::cout << "PASS NCHAR and NVARCHAR2 read as UTF-8, both read paths\n";

        // INTERVALs, including negative spans and the largest fraction.
        dml("INSERT INTO T_INTERVAL VALUES (1, INTERVAL '2-3' YEAR TO MONTH, INTERVAL '3 04:05:06.789012' DAY TO SECOND)",
            "interval 1");
        dml("INSERT INTO T_INTERVAL VALUES (2, INTERVAL '-5-11' YEAR TO MONTH, INTERVAL '-12 23:59:59.5' DAY TO SECOND)",
            "interval 2");
        dml("INSERT INTO T_INTERVAL VALUES (3, INTERVAL '0-0' YEAR TO MONTH, INTERVAL '0 0:0:0' DAY TO SECOND)",
            "interval 3");
        dml("INSERT INTO T_INTERVAL VALUES (4, INTERVAL '9999-11' YEAR(4) TO MONTH, INTERVAL '9999 23:59:59.999999' DAY(4) TO SECOND(6))",
            "interval 4");
        dml("INSERT INTO T_INTERVAL VALUES (5, NULL, NULL)", "interval 5");
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, YM, DS FROM T_INTERVAL ORDER BY ID')"),
                                   std::string("raw.T_INTERVAL")}) {
            auto result = Run(admin,
                              "SELECT id, ym = INTERVAL 27 MONTH AS a, ds = INTERVAL '3 days 04:05:06.789012' AS b, "
                              "ym = INTERVAL (-71) MONTH AS c, ds = INTERVAL '-12 days -23:59:59.5' AS d, "
                              "ym = INTERVAL 0 MONTH AS e, ds = INTERVAL 0 SECOND AS f, "
                              "ym = INTERVAL (9999 * 12 + 11) MONTH AS g, ds = INTERVAL '9999 days 23:59:59.999999' AS h, "
                              "ym IS NULL AS i, ds IS NULL AS j FROM " + source + " ORDER BY id;",
                              "interval read");
            Check(result->RowCount() == 5, "interval rows");
            Check(result->GetValue(1, 0).ToString() == "true" && result->GetValue(2, 0).ToString() == "true", "interval positive");
            Check(result->GetValue(3, 1).ToString() == "true" && result->GetValue(4, 1).ToString() == "true", "interval negative");
            Check(result->GetValue(5, 2).ToString() == "true" && result->GetValue(6, 2).ToString() == "true", "interval zero");
            Check(result->GetValue(7, 3).ToString() == "true" && result->GetValue(8, 3).ToString() == "true", "interval at the limits");
            Check(result->GetValue(9, 4).ToString() == "true" && result->GetValue(10, 4).ToString() == "true", "interval NULL");
        }
        // A fraction finer than DuckDB's microsecond is refused, not rounded.
        dml("INSERT INTO T_FINE VALUES (INTERVAL '1 00:00:00.123456789' DAY TO SECOND(9))", "fine insert");
        auto fine = admin.Query("SELECT * FROM oracle_query('rt', 'SELECT D FROM T_FINE');");
        Check(fine->HasError() && fine->GetError().find("sub-microsecond") != std::string::npos, "fine fraction refused");
        std::cout << "PASS INTERVAL YEAR TO MONTH and DAY TO SECOND\n";

        // ROWID and UROWID against Oracle's own text for the same row.
        dml("INSERT INTO T_ROWID (ID) VALUES (1)", "rowid 1");
        dml("INSERT INTO T_ROWID (ID) VALUES (2)", "rowid 2");
        dml("INSERT INTO T_ROWID (ID) VALUES (3)", "rowid 3");
        dml("UPDATE T_ROWID SET R = ROWID, U = ROWID WHERE ID IN (1, 2)", "rowid fill");
        for (const auto &source :
             {std::string("oracle_query('rt', 'SELECT ID, R, U, ROWIDTOCHAR(R) AS RC, CAST(U AS VARCHAR2(200)) AS UC, "
                          "ROWIDTOCHAR(ROWID) AS OWN FROM T_ROWID ORDER BY ID')")}) {
            auto result = Run(admin, "SELECT id, r, u, rc, uc, own FROM " + source + " ORDER BY id;", "rowid read");
            Check(result->RowCount() == 3, "rowid rows");
            for (idx_t row = 0; row < 2; row++) {
                Check(result->GetValue(1, row).ToString() == result->GetValue(3, row).ToString() &&
                          result->GetValue(1, row).ToString().size() == 18,
                      "ROWID text equals ROWIDTOCHAR");
                Check(result->GetValue(2, row).ToString() == result->GetValue(4, row).ToString(),
                      "UROWID text equals CAST AS VARCHAR2");
                Check(result->GetValue(1, row).ToString() == result->GetValue(5, row).ToString(),
                      "the stored ROWID is the row's own");
            }
            Check(result->GetValue(1, 2).IsNull() && result->GetValue(2, 2).IsNull(), "ROWID NULL");
        }
        // The attached catalog reads them the same way.
        {
            auto result = Run(admin, "SELECT count(*) FROM raw.T_ROWID WHERE r IS NOT NULL AND u IS NOT NULL;", "rowid attached");
            Check(result->GetValue(0, 0).ToString() == "2", "attached ROWID and UROWID");
        }
        // A logical UROWID frames cleanly and is refused with a reason.
        dml("INSERT INTO T_IOT VALUES ('alpha', 1)", "iot 1");
        dml("INSERT INTO T_LOGICAL SELECT 1, ROWID FROM T_IOT", "logical fill");
        auto logical = admin.Query("SELECT * FROM oracle_query('rt', 'SELECT ID, U FROM T_LOGICAL');");
        Check(logical->HasError() && logical->GetError().find("logical UROWID") != std::string::npos,
              "logical UROWID refused with its name");
        auto logical_id = Run(admin, "SELECT id FROM oracle_query('rt', 'SELECT ID FROM T_LOGICAL');", "logical id");
        Check(logical_id->GetValue(0, 0).ToString() == "1", "a table with a logical UROWID is still readable without it");
        std::cout << "PASS ROWID and UROWID equal Oracle's own text; logical UROWID refused\n";

        // LONG and LONG RAW: a short value, NULL, one that needs chunks, and
        // a LONG between two other columns.
        dml("INSERT INTO T_LONG VALUES (1, 'short')", "long 1");
        dml("INSERT INTO T_LONG VALUES (2, NULL)", "long 2");
        dml("INSERT INTO T_LONG VALUES (3, RPAD('ab', 4000, 'cd'))", "long 3");
        dml("INSERT INTO T_LONG VALUES (4, 'h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82')", "long 4");
        dml("INSERT INTO T_LONG_RAW VALUES (1, HEXTORAW('DEADBEEF'))", "long raw 1");
        dml("INSERT INTO T_LONG_RAW VALUES (2, NULL)", "long raw 2");
        dml("INSERT INTO T_LONG_MID VALUES (1, 'xy', 'p')", "mid 1");
        dml("INSERT INTO T_LONG_MID VALUES (2, NULL, 'q')", "mid 2");
        dml("INSERT INTO T_LONG_MID VALUES (3, 'z', NULL)", "mid 3");
        // The LONG tables have no key, so rows are ordered by their own id.
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, L FROM T_LONG')"), std::string("raw.T_LONG")}) {
            auto result = Run(admin, "SELECT id, l FROM " + source + " ORDER BY id;", "long read");
            Check(result->RowCount() == 4, "long rows");
            Check(result->GetValue(1, 0).ToString() == "short" && result->GetValue(1, 1).IsNull(), "long short and NULL");
            std::string expected = "ab";
            while (expected.size() < 4000) {
                expected += "cd";
            }
            expected.resize(4000);
            Check(result->GetValue(1, 2).ToString() == expected, "long of 4000 characters");
            Check(result->GetValue(1, 3).ToString() == "h\xc3\xa9llo \xd0\x9f\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82", "long multibyte");
        }
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT ID, L FROM T_LONG_RAW')"), std::string("raw.T_LONG_RAW")}) {
            auto result = Run(admin, "SELECT id, l FROM " + source + " ORDER BY id;", "long raw read");
            Check(result->RowCount() == 2 && result->GetValue(1, 0).ToString() == "\\xDE\\xAD\\xBE\\xEF" && result->GetValue(1, 1).IsNull(),
                  "long raw value and NULL");
        }
        for (const auto &source : {std::string("oracle_query('rt', 'SELECT A, L, B FROM T_LONG_MID')"), std::string("raw.T_LONG_MID")}) {
            auto result = Run(admin, "SELECT a, l, b FROM " + source + " ORDER BY a;", "long mid read");
            Check(result->RowCount() == 3, "mid rows");
            Check(result->GetValue(1, 0).ToString() == "xy" && result->GetValue(2, 0).ToString() == "p", "mid first");
            Check(result->GetValue(1, 1).IsNull() && result->GetValue(2, 1).ToString() == "q", "mid NULL LONG");
            Check(result->GetValue(1, 2).ToString() == "z" && result->GetValue(2, 2).IsNull(), "mid NULL neighbour");
        }
        std::cout << "PASS LONG and LONG RAW, alone and between other columns\n";

        // A CLOB beside a ROWID: the LOB-prefetch path declines columns it
        // does not know, and the ordinary LOB path has to frame both.
        dml("INSERT INTO T_MIX VALUES (1, TO_CLOB('first'), NULL)", "mix 1");
        dml("INSERT INTO T_MIX VALUES (2, RPAD(TO_CLOB('x'), 9000, 'y'), NULL)", "mix 2");
        dml("UPDATE T_MIX SET R = ROWID", "mix fill");
        auto mix = Run(admin,
                       "SELECT id, length(doc) AS n, r = rc AS same FROM oracle_query('rt', 'SELECT ID, DOC, R, "
                       "ROWIDTOCHAR(R) AS RC FROM T_MIX') ORDER BY id;",
                       "mix read");
        Check(mix->RowCount() == 2 && mix->GetValue(1, 0).ToString() == "5" && mix->GetValue(1, 1).ToString() == "9000" &&
                  mix->GetValue(2, 0).ToString() == "true" && mix->GetValue(2, 1).ToString() == "true",
              "CLOB and ROWID in one row");
        std::cout << "PASS CLOB and ROWID in one row\n";

        // What stays refused: writing into a table with a national column, and
        // filtering on one. A write takes its columns from the dictionary alone,
        // which does not name NVARCHAR2, so the refusal names the column.
        auto write = admin.Query("INSERT INTO raw.T_NATIONAL VALUES (9, 'x', 'y');");
        Check(write->HasError() && write->GetError().find("\"NV\"") != std::string::npos,
              "writing a national column is refused");
        Run(admin, "SET oracle_filter_pushdown = true;", "pushdown on");
        auto filtered = admin.Query("SELECT * FROM raw.T_NATIONAL WHERE nv = 'plain';");
        Check(filtered->HasError() && filtered->GetError().find("\"NV\"") != std::string::npos,
              "filtering on a national column is refused when pushed down");
        Run(admin, "SET oracle_filter_pushdown = false;", "pushdown off");
        auto unfiltered = Run(admin, "SELECT count(*) FROM raw.T_NATIONAL WHERE nv = 'plain';", "local filter");
        Check(unfiltered->GetValue(0, 0).ToString() == "1", "the same filter runs in DuckDB when it is not pushed down");
        std::cout << "PASS national columns are read-only and never filtered remotely\n";
        Run(admin, "DETACH raw;", "detach");
    } catch (const std::exception &error) {
        std::cerr << "live test stopped" << (std::string(error.what()) == "live check failed" ? "" : ": error") << "\n";
        status = 1;
    }
    if (created) {
        try {
            (void)admin.Query("DETACH IF EXISTS raw;");
            auto left = Run(admin,
                            "SELECT * FROM oracle_query('admin', 'SELECT SID || '','' || SERIAL# AS S FROM V$SESSION "
                            "WHERE USERNAME = ''" + user + "''');",
                            "cleanup sessions");
            for (idx_t row = 0; row < left->RowCount(); row++) {
                (void)admin.Query("SELECT * FROM oracle_execute_admin('admin', 'ALTER SYSTEM KILL SESSION ''" +
                                  left->GetValue(0, row).ToString() + "'' IMMEDIATE');");
            }
            auto dropped = admin.Query("SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');");
            if (dropped->HasError()) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                Run(admin, "SELECT * FROM oracle_execute_admin('admin', 'DROP USER " + user + " CASCADE');", "drop user");
            }
            Check(Scalar(admin,
                         "SELECT * FROM oracle_query('admin', 'SELECT (SELECT COUNT(*) FROM DBA_USERS WHERE USERNAME = ''" +
                             user + "'') || ''/'' || (SELECT COUNT(*) FROM V$SESSION WHERE USERNAME = ''" + user +
                             "'') AS S FROM DUAL');",
                         "cleanup check") == "0/0",
                  "test user and sessions gone");
            std::cout << "PASS cleanup 0/0\n";
        } catch (const std::exception &) {
            std::cerr << "FAIL cleanup\n";
            status = 1;
        }
    }
    return status;
}
