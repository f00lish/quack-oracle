#pragma once

#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/io_deadline.hpp"
#include "oracle_scanner/protocol_error.hpp"

#include <memory>
#include <mutex>

namespace oracle_scanner {

// Which caller's IO deadline a session obeys, switchable for the session's
// life. A session reused across DuckDB transactions belongs to a different
// caller each time, and that caller's deadline and interrupt must reach the
// socket; the deadline source a session was opened with cannot follow it.
//
// OracleIoDeadline itself is shared with companion extensions through
// oracle_io_deadline.hpp, so its layout cannot change. The binding refers to
// one instead of extending it, and stays private to this extension.
class OracleIoDeadlineBinding {
public:
    explicit OracleIoDeadlineBinding(std::shared_ptr<OracleIoDeadline> source_p = nullptr)
        : source(std::move(source_p)) {
    }

    OracleIoDeadline::Deadline Get() const {
        std::shared_ptr<OracleIoDeadline> current;
        {
            std::lock_guard<std::mutex> guard(lock);
            current = source;
        }
        return current ? current->Get() : std::nullopt;
    }

    // Binds the session to a caller's source, or to none between callers.
    void Bind(std::shared_ptr<OracleIoDeadline> source_p) {
        std::lock_guard<std::mutex> guard(lock);
        source = std::move(source_p);
    }

    bool Bound() const {
        std::lock_guard<std::mutex> guard(lock);
        return source != nullptr;
    }

private:
    mutable std::mutex lock;
    std::shared_ptr<OracleIoDeadline> source;
};

// OracleDeadlineStream, reading the caller's deadline through a binding.
class OracleBoundDeadlineStream final : public ByteStream {
public:
    OracleBoundDeadlineStream(std::unique_ptr<ByteStream> inner_p, std::shared_ptr<OracleIoDeadlineBinding> binding_p)
        : inner(std::move(inner_p)), binding(std::move(binding_p)) {
    }
    size_t Read(uint8_t *destination, size_t size) override {
        Apply();
        return inner->Read(destination, size);
    }
    size_t Write(const uint8_t *bytes, size_t size) override {
        Apply();
        return inner->Write(bytes, size);
    }
    void SendUrgent(uint8_t value) override {
        Apply();
        inner->SendUrgent(value);
    }
    void SetDeadline(OracleIoDeadline::Deadline value) override {
        establishment = value;
        Apply(false);
    }
    void Close() override {
        inner->Close();
    }

private:
    std::unique_ptr<ByteStream> inner;
    std::shared_ptr<OracleIoDeadlineBinding> binding;
    OracleIoDeadline::Deadline establishment;
    void Apply(bool check = true) {
        auto deadline = binding->Get();
        if (check && deadline && std::chrono::steady_clock::now() >= *deadline) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED, "Oracle publication IO deadline expired");
        }
        if (establishment && (!deadline || *establishment < *deadline)) {
            deadline = establishment;
        }
        inner->SetDeadline(deadline);
    }
};

} // namespace oracle_scanner
