#!/usr/bin/env bash
# Build the opt-in public-session CLOB concurrency regression without DuckDB.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
output="${1:-${TMPDIR:-/tmp}/oracle_scanner_shared_lob_live_test}"
sources=()
while IFS= read -r source; do
    [[ -f "${source}" ]] || { echo "missing runtime source" >&2; exit 1; }
    sources+=("${source}")
done < <(awk '/add_executable\(oracle_scanner_protocol_test/,/\)$/' CMakeLists.txt |
             rg -o 'src/[a-z0-9_]*\.cpp')
[[ ${#sources[@]} -gt 0 ]] || { echo "no runtime sources" >&2; exit 1; }
read -r -a openssl_flags <<<"${OPENSSL_FLAGS:-$(pkg-config --cflags --libs openssl)}"
compile_flags=(-O0)
if [[ "${ORACLE_SCANNER_TEST_TSAN:-0}" == 1 ]]; then
    compile_flags=(-g -O1 -fsanitize=thread)
fi
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT
"${CXX:-c++}" -std=c++17 -w -c duckdb/third_party/miniz/miniz.cpp -o "${scratch}/miniz.o"
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror "${compile_flags[@]}" \
    -Isrc/include -Iduckdb/third_party/miniz \
    test/cpp/shared_lob_live_test.cpp "${sources[@]}" "${scratch}/miniz.o" \
    "${openssl_flags[@]}" -o "${output}"
echo "built ordinary CLOB concurrency regression; live execution is explicit"
