#pragma once

#include "oracle_scanner/protocol_error.hpp"
#include <mutex>

namespace oracle_scanner {

// Client result-delivery policy only. No fabricated Oracle code, extra query,
// drain request or replay. The normal reader still owns its current response.
class NativeFetchCancellation {
public:
    template <class Send>
    void Request(Send send) {
        std::lock_guard<std::mutex> guard(mutex);
        RequireUsableLocked();
        pending = true;
        try {
            send();
        } catch (const ProtocolError &error) {
            // The existing TCPS path rejects before sending anything.
            pending = false;
            if (error.Kind() != ProtocolErrorKind::UNSUPPORTED) { unusable = true; }
            throw;
        } catch (...) {
            pending = false;
            unusable = true;
            throw;
        }
    }

    void RequireUsable() const {
        std::lock_guard<std::mutex> guard(mutex);
        RequireUsableLocked();
    }

    void CompleteFetch() {
        std::lock_guard<std::mutex> guard(mutex);
        if (pending || unusable) {
            unusable = true;
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                "Oracle fetch cancelled locally; close the session before reuse");
        }
    }

    // Non-cursor result delivery obeys the same accepted-cancellation state.
    void CompleteOperation() {
        std::lock_guard<std::mutex> guard(mutex);
        if (pending || unusable) {
            unusable = true;
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                "Oracle operation cancelled locally; close the session before reuse");
        }
    }

    void ObserveError(const ProtocolError &error) {
        std::lock_guard<std::mutex> guard(mutex);
        if (pending && !unusable && error.OracleCode() == 1013) {
            // This is the server response already read by the normal call.
            pending = false;
        } else if (pending) {
            unusable = true;
        }
    }

    void ObserveUnknownError() {
        std::lock_guard<std::mutex> guard(mutex);
        if (pending) { unusable = true; }
    }

    bool CanUseConnection() const {
        std::lock_guard<std::mutex> guard(mutex);
        return !pending && !unusable;
    }

private:
    void RequireUsableLocked() const {
        if (pending || unusable) {
            throw ProtocolError(ProtocolErrorKind::INVALID_STATE,
                                "Oracle cancellation pending or session unusable; close before reuse");
        }
    }
    mutable std::mutex mutex;
    bool pending = false;
    bool unusable = false;
};

} // namespace oracle_scanner
