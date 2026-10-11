// Ordinary public session API only; no packet fixtures, proxy or SQL retry.
#include "oracle_scanner/native_session.hpp"
#include "oracle_scanner/descriptor_parser.hpp"
#include "oracle_scanner/wallet_archive.hpp"
#include <atomic>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <thread>
#include <vector>

using namespace oracle_scanner;

static std::string Env(const char *name) {
    const auto value = std::getenv(name);
    if (!value || !*value) {
        throw std::runtime_error("missing configuration");
    }
    return value;
}

static ConnectionConfig Config() {
    ConnectionConfig config;
    if (std::getenv("ORACLE_SCANNER_LOB_WALLET")) {
        config.wallet_pem_file = Env("ORACLE_SCANNER_LOB_WALLET");
        const auto parsed = ParseConnectDescriptor(FindTnsAliasDescriptor(
            ReadWalletTnsNamesArchive(config.wallet_pem_file), Env("ORACLE_SCANNER_LOB_ALIAS")));
        if (parsed.endpoints.size() != 1 || parsed.endpoints[0].protocol != TransportProtocol::TCPS) {
            throw std::runtime_error("single TCPS address required");
        }
        config.host = parsed.endpoints[0].host;
        config.port = parsed.endpoints[0].port;
        config.service_name = parsed.service_name;
        config.instance_name = parsed.instance_name;
        config.server_type = parsed.server_type;
        config.protocol = TransportProtocol::TCPS;
        config.tls_server_name = config.host;
        config.tls_server_cert_dn = parsed.server_cert_dn;
    } else {
        config.host = Env("ORACLE_SCANNER_LOB_HOST");
        const auto port = std::stoul(Env("ORACLE_SCANNER_LOB_PORT"));
        if (port == 0 || port > 65535) {
            throw std::runtime_error("invalid port");
        }
        config.port = static_cast<uint16_t>(port);
        config.service_name = Env("ORACLE_SCANNER_LOB_SERVICE");
    }
    config.user = Env("ORACLE_SCANNER_LOB_USER");
    config.client_program = "native_shared_lob_regression";
    config.connect_timeout_seconds = 10;
    config.read_timeout_seconds = 20;
    config.routing.retry_count = 0;
    config.routing.failover = false;
    ValidateConnectionConfig(config);
    return config;
}

int main() {
    const char *phase = "configuration";
    try {
        const auto config = Config();
        const auto password = Env("ORACLE_SCANNER_LOB_PASSWORD");
        phase = "connect";
        auto session = NativeOracleSession::Connect(config, password);
        for (int round = 0; round < 8; round++) {
            std::vector<std::unique_ptr<OracleCursor>> cursors;
            std::vector<std::string> expected;
            phase = "query";
            for (int i = 0; i < 4; i++) {
                expected.push_back("native-lob-" + std::to_string(i) + std::string(100, 'x'));
                cursors.push_back(session->Query("SELECT TO_CLOB('" + expected.back() + "') FROM DUAL", {}));
            }
            std::atomic<unsigned> ready {0};
            std::atomic<bool> go {false};
            std::vector<std::exception_ptr> errors(4);
            std::vector<std::thread> threads;
            phase = "fetch";
            for (int i = 0; i < 4; i++) {
                threads.emplace_back([&, i] {
                    ++ready;
                    while (!go.load()) {
                        std::this_thread::yield();
                    }
                    try {
                        const auto rows = cursors[i]->Fetch(2);
                        if (rows.rows.size() != 1 || rows.rows[0].size() != 1 || !rows.rows[0][0] ||
                            std::string(rows.rows[0][0]->begin(), rows.rows[0][0]->end()) != expected[i]) {
                            throw std::runtime_error("unexpected result");
                        }
                    } catch (...) {
                        errors[i] = std::current_exception();
                    }
                });
            }
            while (ready.load() != 4) {
                std::this_thread::yield();
            }
            go.store(true);
            for (auto &thread : threads) {
                thread.join();
            }
            for (const auto &error : errors) {
                if (error) {
                    std::rethrow_exception(error);
                }
            }
            phase = "cursor_close";
            for (auto &cursor : cursors) {
                cursor->Close();
            }
        }
        phase = "session_close";
        session->Close();
        std::cout << "PASS native shared CLOB: one session/four cursors/eight rounds/32 exact reads\n";
        return 0;
    } catch (const std::exception &error) {
        // Exception text can contain configuration; only fixed labels are safe.
        const auto *protocol = dynamic_cast<const ProtocolError *>(&error);
        std::cout << "FAIL native shared CLOB phase=" << phase
                  << " class=" << (protocol ? "protocol" : "other") << '\n';
        return 1;
    }
}
