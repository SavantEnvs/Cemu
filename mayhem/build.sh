#!/usr/bin/env bash
#
# mayhem/build.sh — build Cemu's fuzz harnesses (mayhem/harnesses/*.cpp) and the selftest oracle.
#
# Cemu is one monolithic GUI application (wxWidgets, Vulkan/OpenGL, SDL, vcpkg) with no library split;
# its file-format, network and mod parsers are self-contained translation units. So this compiles
# exactly those upstream sources (unchanged, with Cemu's own force-included Common/precompiled.h,
# as upstream's CMake does via target_precompile_headers) into a static library, instrumented with
# $SANITIZER_FLAGS, and links each harness against it. Only Cemu's logging back end is replaced
# (mayhem/harnesses/fuzz_logging.cpp — it would otherwise pull in the config/GUI layer).
#
# Outputs: /mayhem/out/fuzz_<name> (libFuzzer), /mayhem/out/fuzz_<name>-standalone (run-once
# reproducer) and /mayhem/out/cemu_selftest (normal flags, run by mayhem/test.sh).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FMT_PREFIX=/opt/toolchains/deps/fmt-12.1.0
BUILD="$SRC/mayhem/build"   # gitignored by upstream's `build/` rule
OUT="$SRC/out"              # gitignored by upstream's `out/` rule
mkdir -p "$BUILD/test" "$OUT"

# The flags upstream's CMake uses on Linux (src/CMakeLists.txt) + ENABLE_OPENGL (default ON, selects
# kDefaultGraphicsAPI in config/CemuConfig.h).
COMMON_CXXFLAGS=(-std=c++20 -I"$SRC/src" -I"$SRC/mayhem/harnesses" -I"$FMT_PREFIX/include"
  -include "$SRC/src/Common/precompiled.h" -DENABLE_OPENGL
  -Wno-multichar -Wno-invalid-offsetof -Wno-switch -Wno-ignored-attributes
  -Wno-deprecated-enum-enum-conversion -Wno-ambiguous-reversed-operator -w)
LIBS=("$FMT_PREFIX/lib/libfmt.a" -lpugixml -lssl -lcrypto -lz -lpthread -lm)

# Upstream translation units the harnesses reach.
CEMU_SOURCES=(
  src/Cafe/OS/libs/nfc/TagV0.cpp
  src/Cafe/OS/libs/nfc/TLV.cpp
  src/Cafe/OS/libs/nfc/ndef.cpp
  src/Cafe/OS/libs/nfc/stream.cpp
  src/util/IniParser/IniParser.cpp
  src/Cafe/Filesystem/WUD/wud.cpp
  src/Cafe/Filesystem/WUHB/WUHBReader.cpp
  src/Cemu/nex/prudp.cpp
  src/Cemu/nex/nex.cpp
  src/Cemu/nex/nexThread.cpp
  src/Cemu/nex/nexFriends.cpp
  src/util/crypto/md5.cpp
  src/Cemu/FileCache/FileCache.cpp
  src/Common/unix/FileStream_unix.cpp
  src/Cemu/ncrypto/ncrypto.cpp
  src/util/crypto/aes128.cpp
  src/Common/cpu_features.cpp
  src/Common/unix/platform.cpp
  src/util/helpers/helpers.cpp
  src/Cafe/IOSU/legacy/iosu_crypto.cpp
  src/Cemu/PPCAssembler/ppcAssembler.cpp
)
SUPPORT_SOURCES=(mayhem/harnesses/fuzz_logging.cpp)
HARNESSES=(nfc_tag ini wux wuhb prudp nex filecache tmd_ticket expression ppcasm metaxml)
HARNESS_SOURCES=()
for h in "${HARNESSES[@]}"; do HARNESS_SOURCES+=("mayhem/harnesses/fuzz_$h.cpp"); done

# compile_set <objdir> <flags...> -- <sources...>   (parallel; always recompiles, so re-runs are clean)
compile_set() {
  local objdir="$1"; shift
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  printf '%s\n' "$@" | xargs -P "$MAYHEM_JOBS" -I{} sh -c '
    o="$0/$(echo "{}" | tr "/" "_").o"
    exec "$@" -c "{}" -o "$o"' "$objdir" "$CXX" "${flags[@]}"
}

# 1) Sanitized + DWARF-3 project objects, archived so each harness links only what it needs. Two sets:
#    "fuzz" adds SanitizerCoverage (-fsanitize=fuzzer-no-link) for the libFuzzer binaries; "repro" has no
#    coverage hooks so the standalone reproducers also link with an empty SANITIZER_FLAGS.
COV_FLAGS="-fsanitize=fuzzer-no-link"
# UBSan's `alignment` check is relaxed (ASan and every other UBSan check stay on and halting): Cemu is an
# x86-64-only program (precompiled.h includes <immintrin.h>) that reads packed big-endian structures at
# arbitrary byte offsets by design (e.g. prudp.cpp `*(uint16*)(data + 0x02)`, ncrypto.cpp's ticket
# section casts), so the check fires on nearly every input to these parsers and masks the real defects.
RELAX_FLAGS="-fno-sanitize=alignment"
for kind in fuzz repro; do
  extra=""; [ "$kind" = fuzz ] && extra="$COV_FLAGS"
  mkdir -p "$BUILD/$kind"
  # shellcheck disable=SC2086
  compile_set "$BUILD/$kind" "${COMMON_CXXFLAGS[@]}" -O1 $SANITIZER_FLAGS $RELAX_FLAGS $DEBUG_FLAGS $extra -- \
    "${CEMU_SOURCES[@]}" "${SUPPORT_SOURCES[@]}" "${HARNESS_SOURCES[@]}"
  rm -f "$BUILD/libcemu_$kind.a"
  ar rcs "$BUILD/libcemu_$kind.a" $(ls "$BUILD/$kind"/*.o | grep -v '/mayhem_harnesses_')
done

# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$BUILD/lsan_off.o"
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$BUILD/standalone_main.o"

# 2) Each harness twice: libFuzzer binary + standalone reproducer.
for h in "${HARNESSES[@]}"; do
  ho="mayhem_harnesses_fuzz_$h.cpp.o"
  lo="mayhem_harnesses_fuzz_logging.cpp.o"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$BUILD/fuzz/$ho" "$BUILD/fuzz/$lo" "$BUILD/lsan_off.o" \
    "$BUILD/libcemu_fuzz.a" "${LIBS[@]}" -o "$OUT/fuzz_$h"
  # shellcheck disable=SC2086
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$BUILD/standalone_main.o" "$BUILD/repro/$ho" "$BUILD/repro/$lo" "$BUILD/lsan_off.o" \
    "$BUILD/libcemu_repro.a" "${LIBS[@]}" -o "$OUT/fuzz_$h-standalone"
done

# 3) The selftest oracle with NORMAL flags (no sanitizers), CEMU_DEBUG_ASSERT on so upstream's own
#    ExpressionParser_test() assertions are live.
# shellcheck disable=SC2086
compile_set "$BUILD/test" "${COMMON_CXXFLAGS[@]}" -O1 -DCEMU_DEBUG_ASSERT $COVERAGE_FLAGS -- \
  "${CEMU_SOURCES[@]}" "${SUPPORT_SOURCES[@]}" src/Cemu/ExpressionParser/ExpressionParser.cpp mayhem/selftest/cemu_selftest.cpp
# shellcheck disable=SC2086
$CXX $COVERAGE_FLAGS "$BUILD"/test/*.o "${LIBS[@]}" -o "$OUT/cemu_selftest"

echo "built: $(cd "$OUT" && ls | tr '\n' ' ')"
