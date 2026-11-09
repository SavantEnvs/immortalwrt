#!/usr/bin/env bash
#
# mayhem/build.sh — build the fuzz harnesses, their standalone reproducers and the oracle test binaries.
# ImmortalWrt is a firmware build system, so the fuzzed code is its small in-tree C utilities
# (package/utils/{nvram,bcm4908img,osafeloader,fritz-tools}, package/network/services/ead). Each harness
# compiles the utility's own source, so no upstream file is patched or copied.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

M="$SRC/mayhem"
U="$SRC/package/utils"
EAD="$SRC/package/network/services/ead/src"
B="$SRC/build_dir/mayhem"
rm -rf "$B"
mkdir -p "$B/obj" "$B/test"

# project code is always built with coverage instrumentation so the fuzzer sees edges in it
PROJ="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -w"
# Three upstream EAD sources hit benign UB on every message and would halt every input. Each check is
# switched off only for the one translation unit that needs it, and nothing else is relaxed:
#   shift-base:   ead-crypt.c (aes.c, sha1.c) and tinysrp (t_client.c) shift into the sign bit
#   array-bounds: ead-client.c (pw_encrypt_md5.c) computes `S - 4` before an array
EAD_SHIFT="-fno-sanitize=shift-base"
EAD_ARRAY="-fno-sanitize=array-bounds"

# no-op SanCov callbacks for a build with SANITIZER_FLAGS empty: the standalone driver then has no
# sanitizer runtime to provide them
STUB=
if [ -z "$SANITIZER_FLAGS" ]; then
	cat > "$B/obj/sancov_stub.c" <<'STUBSRC'
#include <stdint.h>
void __sanitizer_cov_trace_pc_guard_init(uint32_t *s, uint32_t *e) { (void)s; (void)e; }
void __sanitizer_cov_trace_pc_guard(uint32_t *g) { (void)g; }
void __sanitizer_cov_8bit_counters_init(char *s, char *e) { (void)s; (void)e; }
void __sanitizer_cov_pcs_init(const uintptr_t *s, const uintptr_t *e) { (void)s; (void)e; }
STUBSRC
	$CC -c -w -O1 "$B/obj/sancov_stub.c" -o "$B/obj/sancov_stub.o"
	STUB="$B/obj/sancov_stub.o"
fi

# ---- sanitized project objects ----
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$B/obj/lsan_off.o"
$CC $PROJ -c "$U/nvram/src/nvram.c" -o "$B/obj/nvram.o"
$CC $PROJ -c "$U/nvram/src/crc.c" -o "$B/obj/crc.o"
$CC $PROJ -c "$U/osafeloader/src/md5.c" -o "$B/obj/md5.o"
$CC $PROJ $EAD_SHIFT -include arpa/inet.h -I"$EAD" -c "$EAD/ead-crypt.c" -o "$B/obj/ead-crypt.o"

# tinysrp is part of the ead target: build it out of tree, instrumented, with its old configure
cp -r "$EAD/tinysrp" "$B/tinysrp"
(
	cd "$B/tinysrp"
	export CC CFLAGS="$PROJ $EAD_SHIFT -std=gnu89" LDFLAGS="$SANITIZER_FLAGS"
	./configure >"$B/tinysrp-configure.log" 2>&1 || { tail -30 "$B/tinysrp-configure.log" >&2; exit 1; }
	make libtinysrp.a CFLAGS="$CFLAGS" >"$B/tinysrp-make.log" 2>&1 || { tail -30 "$B/tinysrp-make.log" >&2; exit 1; }
)

# ---- harnesses: libFuzzer binary + standalone reproducer ----
# link <name> <extra compile flags> <objects...>
link() {
	local name="$1" cflags="$2"; shift 2
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -w -I"$SRC" $cflags $LIB_FUZZING_ENGINE \
		"$M/fuzz_$name.c" "$@" "$B/obj/lsan_off.o" -o "$SRC/fuzz_$name"
	$CC $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -w -I"$SRC" $cflags "$STANDALONE_FUZZ_MAIN" \
		"$M/fuzz_$name.c" "$@" "$B/obj/lsan_off.o" $STUB -o "$SRC/fuzz_$name-standalone"
}
link nvram "" "$B/obj/nvram.o" "$B/obj/crc.o"
link bcm4908img "" 
link osafeloader "" "$B/obj/md5.o"
link fritz_tffs ""
link ead_client "$EAD_ARRAY -I$EAD -I$EAD/tinysrp" "$B/obj/ead-crypt.o" "$B/tinysrp/libtinysrp.a"

# ---- oracle: the utilities and self-tests built with the project's normal flags ----
T="-O1 -w $COVERAGE_FLAGS"
$CC $T "$U/bcm4908img/src/bcm4908img.c" -o "$B/test/bcm4908img"
$CC $T "$U/osafeloader/src/osafeloader.c" "$U/osafeloader/src/md5.c" -o "$B/test/osafeloader"
$CC $T "$U/fritz-tools/src/fritz_tffs_read.c" -o "$B/test/fritz_tffs_read"
$CC $T "$M/selftest_nvram.c" "$U/nvram/src/nvram.c" "$U/nvram/src/crc.c" -o "$B/test/selftest_nvram"
$CC $T -I"$EAD" "$M/selftest_ead.c" -o "$B/test/selftest_ead"
