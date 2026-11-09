#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the utilities the fuzz targets cover. mayhem/build.sh built the
# normal-flag binaries under build_dir/mayhem/test; this only runs them on the committed seed images and
# compares their output to exact expected values.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

T="$SRC/build_dir/mayhem/test"
M="$SRC/mayhem"
for b in bcm4908img osafeloader fritz_tffs_read selftest_nvram selftest_ead; do
  [ -x "$T/$b" ] || { echo "missing $T/$b: mayhem/build.sh did not build it" >&2; exit 1; }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/immortalwrt-test-XXXXXX")
trap 'rm -rf "$work"' EXIT

passed=0
failed=0
# check <name> <expected> <actual>
check() {
  if [ "$2" == "$3" ]; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $1" >&2
    echo "--- expected" >&2; printf '%s\n' "$2" >&2
    echo "--- actual" >&2; printf '%s\n' "$3" >&2
  fi
}

# nvram: read a fixture, edit it, commit, read back
exp='boardtype=0x04cf
boardnum=42
et0macaddr=00:11:22:33:44:55
lan_ipaddr=192.168.1.1
wl0_ssid=ImmortalWrt
sdram_init=0x0009
nothere=(null)
after:
wl0_ssid=Edited-SSID
newvar=42
boardnum=(null)
lan_ipaddr=192.168.1.1'
check "nvram get/set/unset/commit round trip" "$exp" "$("$T/selftest_nvram" "$M/fuzz_nvram/testsuite/nvram_basic.bin" 2>&1)"

# ead: seal and open a message with a fixed session key, and reject a tampered one
exp='sealed_len=64
sealed_head=9b2c216368b92bcdc14e10800ca1b764
opened_len=7 done=1 text=hello
tamper=0'
check "ead message seal/open" "$exp" "$("$T/selftest_ead" 2>&1)"

# bcm4908img: image layout and checksum, bootfs listing, extracted sizes
img="$M/fuzz_bcm4908img/testsuite/bcm4908img_basic.bin"
exp=$'bootfs offset:\t0x0\nrootfs offset:\t0x20000\nChecksum:\t0x932f96d5'
act=$("$T/bcm4908img" info -i "$img" 2>&1)
check "bcm4908img info" "$exp" "$act"
act=$("$T/bcm4908img" bootfs -i "$img" ls 2>&1)
check "bcm4908img bootfs ls" $'cferam.000\nvmlinux.lz\nopenwrt.dtb' "$act"
"$T/bcm4908img" extract -i "$img" -t rootfs >"$work/rootfs.bin" 2>/dev/null
check "bcm4908img extract rootfs size" "1024" "$(stat -c %s "$work/rootfs.bin" 2>/dev/null)"
check "bcm4908img extract rootfs magic" "UBI#" "$(head -c 4 "$work/rootfs.bin" 2>/dev/null)"

# osafeloader: header, partition table and extraction
saf="$M/fuzz_osafeloader/testsuite/osafeloader_basic.bin"
exp='Image size: 5632
       MD5: 41c6a02cba84279125bbe295debc0ece
 Partition: os-image (0x100 - 0x400)
 Partition: file-system (0x400 - 0x4cc)
 Partition: partition-table (0x500 - 0x540)'
act=$("$T/osafeloader" info "$saf" 2>&1)
check "osafeloader info" "$exp" "$act"
"$T/osafeloader" extract "$saf" -p os-image -o "$work/os-image.bin" >/dev/null 2>&1
check "osafeloader extract os-image size" "768" "$(stat -c %s "$work/os-image.bin" 2>/dev/null)"

# fritz_tffs_read: key listing and value lookup, both byte orders
for f in le be; do
  flag=
  [ "$f" == be ] && flag=-b
  src="$M/fuzz_fritz_tffs/testsuite/fritz_tffs_$f.bin"
  act=$("$T/fritz_tffs_read" $flag -l -i "$src" 2>&1)
  check "fritz_tffs $f key list" $'firmware_version\nHWRevision\nProductID\nautoload' "$act"
  act=$("$T/fritz_tffs_read" $flag -n ProductID -i "$src" 2>&1)
  check "fritz_tffs $f ProductID" "Fritz_Box_HW209" "$act"
  act=$("$T/fritz_tffs_read" $flag -a -i "$src" 2>&1)
  check "fritz_tffs $f all" $'firmware_version=avm.7.57\nHWRevision=209\nProductID=Fritz_Box_HW209\nautoload=yes' "$act"
done

emit_ctrf immortalwrt-known-answer "$passed" "$failed"
