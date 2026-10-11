#include "oracle_scanner/lob_reader.hpp"
#include <iostream>
#include <stdexcept>

using namespace oracle_scanner;

static void Check(bool value) {
    if (!value) { throw std::runtime_error("LOB reader assertion failed"); }
}

static void CheckContent(bool character, uint64_t units, size_t expected_reads, size_t expected_lengths) {
    size_t reads=0,lengths=0;
    uint64_t next=1;
    auto value=ReadOracleLobContent(character,[&](uint64_t offset,uint64_t amount) {
        ++reads; Check(offset==next);
        const auto served=(std::min)(units-offset+1,amount);
        next+=served;
        TtcLobResponse response;
        response.amount=served;
        response.data.assign(served*(character ? 2 : 1),0x61);
        return response;
    },[&] {++lengths;return units;});
    Check(value.size()==units*(character ? 2 : 1));
    Check(reads==expected_reads && lengths==expected_lengths);
}

static void CheckFailure(ProtocolErrorKind expected, const TtcLobResponse &first, uint64_t total,
                         const TtcLobResponse &later) {
    size_t calls=0;
    try {
        ReadOracleLobContent(false,[&](uint64_t,uint64_t) {return ++calls==1 ? first : later;},[&] {return total;});
    } catch (const ProtocolError &error) {
        Check(error.Kind()==expected);return;
    }
    throw std::runtime_error("invalid LOB response accepted");
}

int main() {
    try {
        for (bool character : {false,true}) {
            const uint64_t chunk=character ? 32767 : 65536;
            CheckContent(character,0,1,0);
            CheckContent(character,1,1,0);
            CheckContent(character,chunk-1,1,0);
            CheckContent(character,chunk,1,1);
            CheckContent(character,chunk+1,2,1);
            CheckContent(character,chunk*2,2,1);
            CheckContent(character,chunk*2+1,3,1);
        }
        TtcLobResponse first;first.amount=65536;first.data.assign(65536,0x61);
        CheckFailure(ProtocolErrorKind::MALFORMED,first,65535,{});
        CheckFailure(ProtocolErrorKind::TRUNCATED,first,65537,{});
        TtcLobResponse bad;bad.amount=65537;bad.data.assign(65537,0x61);
        CheckFailure(ProtocolErrorKind::MALFORMED,bad,65537,{});
        bad.amount=0;bad.data={1};
        CheckFailure(ProtocolErrorKind::MALFORMED,bad,0,{});
        bad.amount=1;bad.data.clear();
        CheckFailure(ProtocolErrorKind::MALFORMED,bad,0,{});
        bad.amount=1;bad.data.assign(65537,1);
        CheckFailure(ProtocolErrorKind::MALFORMED,bad,0,{});
        std::cout<<"PASS LOB reader: short reads, exact boundaries, long offsets, call counts, malformed/truncated responses\n";
        return 0;
    } catch (...) {
        std::cout<<"FAIL LOB reader\n";return 1;
    }
}
