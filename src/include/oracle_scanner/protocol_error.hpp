#pragma once

#include <stdexcept>
#include <string>
#include <cstdint>
#include <optional>

namespace oracle_scanner {

enum class ProtocolErrorKind {
    TRUNCATED,
    MALFORMED,
    LIMIT_EXCEEDED,
    INVALID_STATE,
    UNSUPPORTED
};

class ProtocolError : public std::runtime_error {
public:
    ProtocolError(ProtocolErrorKind kind, const std::string &message,
                  std::optional<uint32_t> oracle_code_p = std::nullopt)
        : std::runtime_error(message), kind(kind), oracle_code(oracle_code_p) {
    }

    ProtocolErrorKind Kind() const {
        return kind;
    }

    std::optional<uint32_t> OracleCode() const {
        return oracle_code;
    }

private:
    ProtocolErrorKind kind;
    std::optional<uint32_t> oracle_code;
};

} // namespace oracle_scanner
