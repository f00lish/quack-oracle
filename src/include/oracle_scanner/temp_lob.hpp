#pragma once

#include "oracle_scanner/session.hpp"
#include "oracle_scanner/ttc_lob.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace oracle_scanner {

// Writing a LOB value past what an ordinary bind carries goes through a
// temporary LOB: the content is written into one the server creates for the
// session, and the statement binds its locator. python-oracledb Thin does the
// same when it is handed a LOB; the shapes are in PROVENANCE.md.
//
// A bind whose `lob_content` is set and whose value is at most this many bytes
// stays an ordinary VARCHAR2 or RAW bind, which is the form every smaller
// value has always used.
constexpr size_t TEMP_LOB_THRESHOLD_BYTES = size_t {8} << 20U;
// The most one bind may carry. The server's temporary tablespace is the real
// limit; this keeps a runaway value from being sent at all.
constexpr size_t TEMP_LOB_MAXIMUM_BYTES = size_t {1} << 30U;
// One LOB_OP write carries at most this much of the source, so a write is a
// bounded message however large the value is.
constexpr size_t TEMP_LOB_WRITE_CHUNK_BYTES = size_t {2} << 20U;

// The three operations a temporary LOB needs, behind the seam that lets a
// scripted writer drive the logic without a connection.
class TemporaryLobWriter {
public:
    virtual ~TemporaryLobWriter() = default;
    virtual std::vector<uint8_t> Create(TtcTempLobKind kind) = 0;
    //! `offset` is 1-based, in UTF-16 units for a CLOB and bytes for a BLOB.
    //! Returns the locator to use from here on.
    virtual std::vector<uint8_t> Write(const std::vector<uint8_t> &locator, uint64_t offset,
                                       const std::vector<uint8_t> &data) = 0;
    virtual void Free(const std::vector<std::vector<uint8_t>> &locators) = 0;
};

// Rewrites the binds of one statement, or of one group of rows of an array
// DML, so that every LOB value too large for an ordinary bind travels as a
// temporary LOB, and releases the LOBs afterwards.
class TemporaryLobScope {
public:
    explicit TemporaryLobScope(TemporaryLobWriter &writer);
    TemporaryLobScope(const TemporaryLobScope &) = delete;
    TemporaryLobScope &operator=(const TemporaryLobScope &) = delete;

    static bool Needed(const std::vector<OracleBind> &binds);
    static bool NeededRows(const std::vector<std::vector<OracleBind>> &rows, size_t begin, size_t end);

    void Convert(std::vector<OracleBind> &binds);
    //! Array DML declares each bind's metadata once for every row, so when one
    //! row's value needs a temporary LOB, that column is bound by locator in
    //! every row of the group.
    void ConvertRows(std::vector<std::vector<OracleBind>> &rows);

    //! Frees what was created. Throws if the server refuses.
    void Release();
    //! The same, for the failure path, where nothing may throw.
    void ReleaseQuietly() noexcept;

private:
    void ConvertBind(OracleBind &bind);

    TemporaryLobWriter &writer;
    std::vector<std::vector<uint8_t>> locators;
};

} // namespace oracle_scanner
