#pragma once
#include "oracle_scanner/byte_stream.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include <mutex>
#include <algorithm>

namespace oracle_scanner {

// Shared only by sessions belonging to one caller connection. It carries no
// credentials, endpoint or protocol state; scopes are nested on that caller.
class OracleIoDeadline {
public:
    using Deadline = std::optional<std::chrono::steady_clock::time_point>;
    Deadline Get() const { std::lock_guard<std::mutex> guard(lock); return deadline; }
    void Set(Deadline value) { std::lock_guard<std::mutex> guard(lock); deadline = value; }
private:
    mutable std::mutex lock;
    Deadline deadline;
};

class ScopedOracleIoDeadline {
public:
    ScopedOracleIoDeadline(std::shared_ptr<OracleIoDeadline> source_p, std::chrono::steady_clock::time_point deadline)
        : source(std::move(source_p)), previous(source->Get()) {
        source->Set(previous ? std::min(*previous,deadline) : deadline);
    }
    ~ScopedOracleIoDeadline() { source->Set(previous); }
    ScopedOracleIoDeadline(const ScopedOracleIoDeadline &) = delete;
    ScopedOracleIoDeadline &operator=(const ScopedOracleIoDeadline &) = delete;
private:
    std::shared_ptr<OracleIoDeadline> source;
    OracleIoDeadline::Deadline previous;
};

// The establishment deadline and the caller deadline compose. Removing the
// former after auth does not remove an active publication budget. Updating
// the source reaches already-authenticated sessions before their next IO.
class OracleDeadlineStream final : public ByteStream {
public:
    OracleDeadlineStream(std::unique_ptr<ByteStream> inner_p, std::shared_ptr<OracleIoDeadline> source_p)
        : inner(std::move(inner_p)), source(std::move(source_p)) {}
    size_t Read(uint8_t *destination, size_t size) override { Apply(); return inner->Read(destination,size); }
    size_t Write(const uint8_t *bytes, size_t size) override { Apply(); return inner->Write(bytes,size); }
    void SendUrgent(uint8_t value) override { Apply(); inner->SendUrgent(value); }
    void SetDeadline(OracleIoDeadline::Deadline value) override { establishment = value; Apply(false); }
    void Close() override { inner->Close(); }
private:
    std::unique_ptr<ByteStream> inner;
    std::shared_ptr<OracleIoDeadline> source;
    OracleIoDeadline::Deadline establishment;
    void Apply(bool check = true) {
        auto deadline = source->Get();
        if (check && deadline && std::chrono::steady_clock::now() >= *deadline) {
            throw ProtocolError(ProtocolErrorKind::TRUNCATED,"Oracle publication IO deadline expired");
        }
        if (establishment && (!deadline || *establishment < *deadline)) { deadline = establishment; }
        inner->SetDeadline(deadline);
    }
};
}
