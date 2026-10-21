#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace oracle_scanner {

struct OracleDateTime {
    int32_t year = 1970;
    uint8_t month = 1;
    uint8_t day = 1;
    uint8_t hour = 0;
    uint8_t minute = 0;
    uint8_t second = 0;
    uint32_t nanosecond = 0;
    int16_t offset_minutes = 0;
    bool has_offset = false;
};

std::vector<uint8_t> EncodeOracleDate(const OracleDateTime &value);
OracleDateTime DecodeOracleDate(const std::vector<uint8_t> &wire);
std::vector<uint8_t> EncodeOracleTimestamp(const OracleDateTime &value, bool with_time_zone);
OracleDateTime DecodeOracleTimestamp(const std::vector<uint8_t> &wire);

std::vector<uint8_t> EncodeOracleBinaryFloat(float value);
std::vector<uint8_t> EncodeOracleBinaryDouble(double value);
float DecodeOracleBinaryFloat(const std::vector<uint8_t> &wire);
double DecodeOracleBinaryDouble(const std::vector<uint8_t> &wire);

// Converts through decimal text so Oracle NUMBER values never pass through a
// binary floating-point representation. The encoder accepts ordinary or
// scientific decimal notation and emits the canonical base-100 wire form.
std::vector<uint8_t> EncodeOracleNumber(const std::string &decimal);
std::string DecodeOracleNumber(const std::vector<uint8_t> &wire);

// The same value as an integer, without the text: present only when the wire
// form is well formed, holds a whole number and fits int64_t. A caller falls
// back to DecodeOracleNumber for everything else, which is also where a
// malformed value is reported.
std::optional<int64_t> TryDecodeOracleInteger(const std::vector<uint8_t> &wire);

} // namespace oracle_scanner
