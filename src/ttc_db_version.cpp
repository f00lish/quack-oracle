#include "oracle_scanner/ttc_db_version.hpp"

#include "oracle_scanner/byte_buffer.hpp"
#include "oracle_scanner/protocol_error.hpp"
#include "oracle_scanner/ttc_auth.hpp"
#include "oracle_scanner/ttc_parameter.hpp"

#include <string>

namespace oracle_scanner {

namespace {

constexpr size_t MAX_DB_VERSION_TEXT_BYTES = 65535;

} // namespace

std::vector<uint8_t> EncodeTtcDbVersionRequest(uint8_t sequence) {
    ByteWriter writer;
    writer.WriteByte(TTC_MESSAGE_FUNCTION).WriteByte(TTC_FUNCTION_DB_VERSION).WriteByte(sequence);
    writer.WriteByte(1);
    writer.WriteUB2(0x100);
    writer.WriteByte(1);
    writer.WriteByte(1);
    return writer.Take();
}

TtcDbVersion DecodeTtcDbVersionResponse(const std::vector<uint8_t> &message,
                                        TtcChunkEncoding chunk_encoding) {
    ByteReader reader(message);
    try {
        if (reader.ReadByte() != TTC_MESSAGE_PARAMETER) {
            throw ProtocolError(ProtocolErrorKind::MALFORMED, "expected a TTC PARAMETER database version response");
        }
        TtcDbVersion result;
        const auto info = reader.ReadLengthPrefixed(MAX_DB_VERSION_TEXT_BYTES, chunk_encoding);
        if (info) {
            result.info.assign(info->begin(), info->end());
        }
        result.number = reader.ReadUB4();
        return result;
    } catch (const ProtocolError &error) {
        throw ProtocolError(error.Kind(), "TTC database version response at offset " + std::to_string(reader.Position()) +
                                              ": " + error.what());
    }
}

} // namespace oracle_scanner
