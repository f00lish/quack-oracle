#pragma once

#include "oracle_scanner/session.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace oracle_scanner {

class OracleIoDeadline;
class OracleIoDeadlineBinding;

struct OracleTransactionPoolCounters {
    uint64_t opened = 0;
    uint64_t reused = 0;
    uint64_t returned = 0;
    uint64_t closed = 0;
    uint64_t probe_failures = 0;
    size_t idle = 0;
    size_t leased = 0;
};

// Idle sessions kept between the transactions of one attached catalog, so a
// transaction does not pay for a connect and an authentication every time.
//
// The owner is the attached catalog, not a ClientContext: DuckLake opens a
// fresh metadata Connection per transaction and destroys its context between
// autocommit statements, so anything a context owns is gone before the next
// transaction could use it. Every session here comes from the one secret the
// catalog resolved at ATTACH, so users and configurations cannot mix.
//
// A session is leased whole to one transaction, never shared between two.
// The pool never decides on its own that a session is clean: Release is the
// caller's statement that the transaction ended in a confirmed COMMIT or
// ROLLBACK, and even then the session must say it is ReadyForReuse and have
// no other holder. Anything else is closed. An idle session must answer a
// probe before it is handed out; the probe is the only statement a session
// sends before the transaction's own work begins, so a session that died idle
// is replaced without anything the transaction did being sent twice.
class OracleTransactionSessionPool {
public:
    // Opens a session whose IO deadline is read through the given binding.
    using Opener = std::function<std::shared_ptr<OracleSession>(std::shared_ptr<OracleIoDeadlineBinding>)>;
    // Proves an idle session still talks to its server; throws if not.
    using Probe = std::function<void(OracleSession &)>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    static constexpr std::chrono::seconds DEFAULT_MAXIMUM_IDLE_TIME {300};

    OracleTransactionSessionPool(size_t maximum_idle, Opener opener, Probe probe = SelectFromDual,
                                 std::chrono::steady_clock::duration maximum_idle_time = DEFAULT_MAXIMUM_IDLE_TIME,
                                 Clock clock = std::chrono::steady_clock::now);
    ~OracleTransactionSessionPool();

    OracleTransactionSessionPool(const OracleTransactionSessionPool &) = delete;
    OracleTransactionSessionPool &operator=(const OracleTransactionSessionPool &) = delete;

    // A session for one transaction, bound to the caller's deadline. Reused
    // only after it answered the probe; opened otherwise. A failure here is
    // before any of the transaction's statements.
    std::shared_ptr<OracleSession> Acquire(std::shared_ptr<OracleIoDeadline> caller);

    // Call only after the transaction's COMMIT or ROLLBACK was acknowledged.
    // Keeps the session when it is clean, sole-owned and the pool has room;
    // closes it otherwise. Returns whether it was kept.
    bool Release(std::shared_ptr<OracleSession> session) noexcept;

    // Closes a leased session that must not be reused: poisoned, an unknown
    // COMMIT outcome, a failed rollback.
    void Discard(std::shared_ptr<OracleSession> session) noexcept;

    // Closes every idle session, and makes Release close from now on. The
    // owner calls it when it is detached or destroyed.
    void Close() noexcept;

    OracleTransactionPoolCounters Counters() const;

    static void SelectFromDual(OracleSession &session);

private:
    struct Idle {
        std::shared_ptr<OracleSession> session;
        std::chrono::steady_clock::time_point since;
    };

    static void CloseQuietly(const std::shared_ptr<OracleSession> &session) noexcept;
    std::vector<std::shared_ptr<OracleSession>> TakeExpiredLocked();

    mutable std::mutex mutex;
    size_t maximum_idle;
    Opener opener;
    Probe probe;
    std::chrono::steady_clock::duration maximum_idle_time;
    Clock clock;
    bool closed = false;
    std::vector<Idle> idle;
    OracleTransactionPoolCounters counters;
};

} // namespace oracle_scanner
