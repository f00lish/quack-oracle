#include "oracle_scanner/temp_lob.hpp"

#include "oracle_scanner/protocol_error.hpp"

#include <algorithm>
#include <string>

namespace oracle_scanner {

namespace {

bool IsLargeLob(const OracleBind &bind) {
    return bind.lob_content != 0 && bind.value && bind.value->size() > TEMP_LOB_THRESHOLD_BYTES;
}

// Splits UTF-8 into pieces of about `limit` bytes that never cut a character,
// so each piece converts to UTF-16 on its own.
size_t Utf8PieceEnd(const std::vector<uint8_t> &text, size_t begin, size_t limit) {
    size_t end = (std::min)(text.size(), begin + limit);
    while (end < text.size() && end > begin && (text[end] & 0xC0U) == 0x80U) {
        end--;
    }
    if (end == begin) {
        // A single character longer than the limit does not exist in UTF-8;
        // this only guards against input that is not UTF-8 at all.
        throw ProtocolError(ProtocolErrorKind::MALFORMED, "text is not valid UTF-8");
    }
    return end;
}

} // namespace

TemporaryLobScope::TemporaryLobScope(TemporaryLobWriter &writer_p) : writer(writer_p) {
}

bool TemporaryLobScope::Needed(const std::vector<OracleBind> &binds) {
    return std::any_of(binds.begin(), binds.end(), IsLargeLob);
}

bool TemporaryLobScope::NeededRows(const std::vector<std::vector<OracleBind>> &rows, size_t begin, size_t end) {
    for (size_t index = begin; index < end && index < rows.size(); index++) {
        if (Needed(rows[index])) {
            return true;
        }
    }
    return false;
}

void TemporaryLobScope::ConvertBind(OracleBind &bind) {
    const bool character = bind.lob_content == 112;
    if (!bind.value) {
        bind.oracle_type = bind.lob_content;
        bind.character_set_form = 0;
        bind.maximum_bytes = 0;
        bind.lob_content = 0;
        return;
    }
    if (bind.value->size() > TEMP_LOB_MAXIMUM_BYTES) {
        throw ProtocolError(ProtocolErrorKind::LIMIT_EXCEEDED, "a LOB value exceeds the supported size");
    }
    auto locator = writer.Create(character ? TtcTempLobKind::CLOB : TtcTempLobKind::BLOB);
    // Recorded as soon as it exists, so a write that fails still releases it.
    locators.push_back(locator);
    const auto slot = locators.size() - 1;
    uint64_t offset = 1;
    const auto &content = *bind.value;
    for (size_t begin = 0; begin < content.size();) {
        const auto end = character ? Utf8PieceEnd(content, begin, TEMP_LOB_WRITE_CHUNK_BYTES)
                                   : (std::min)(content.size(), begin + TEMP_LOB_WRITE_CHUNK_BYTES);
        std::vector<uint8_t> piece;
        if (character) {
            piece = EncodeUtf8ToUtf16Be(std::string(content.begin() + static_cast<std::ptrdiff_t>(begin),
                                                    content.begin() + static_cast<std::ptrdiff_t>(end)));
        } else {
            piece.assign(content.begin() + static_cast<std::ptrdiff_t>(begin),
                         content.begin() + static_cast<std::ptrdiff_t>(end));
        }
        locator = writer.Write(locator, offset, piece);
        locators[slot] = locator;
        offset += character ? piece.size() / 2 : piece.size();
        begin = end;
    }
    bind.oracle_type = bind.lob_content;
    bind.value = locator;
    bind.character_set_form = 0;
    bind.maximum_bytes = 0;
    bind.lob_content = 0;
}

void TemporaryLobScope::Convert(std::vector<OracleBind> &binds) {
    for (auto &bind : binds) {
        if (IsLargeLob(bind)) {
            ConvertBind(bind);
        }
    }
}

void TemporaryLobScope::ConvertRows(std::vector<std::vector<OracleBind>> &rows) {
    if (rows.empty()) {
        return;
    }
    const auto width = rows.front().size();
    for (size_t column = 0; column < width; column++) {
        bool large = false;
        for (const auto &row : rows) {
            if (column < row.size() && IsLargeLob(row[column])) {
                large = true;
                break;
            }
        }
        if (!large) {
            continue;
        }
        for (auto &row : rows) {
            if (column < row.size() && row[column].lob_content != 0) {
                ConvertBind(row[column]);
            }
        }
    }
}

void TemporaryLobScope::Release() {
    if (locators.empty()) {
        return;
    }
    auto pending = std::move(locators);
    locators.clear();
    writer.Free(pending);
}

void TemporaryLobScope::ReleaseQuietly() noexcept {
    try {
        Release();
    } catch (...) {
        // The operation has already failed, and the session is closed or
        // poisoned by whatever failed it; its temporary LOBs end with it.
    }
}

} // namespace oracle_scanner
