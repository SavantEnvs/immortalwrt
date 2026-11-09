/*
 * In-process harness for ImmortalWrt's osafeloader tool (TP-Link SafeLoader firmware container: header
 * with image size + salted MD5, vendor info, "fwup-ptn" partition table). The tool's own source is
 * compiled into this file so its static `info` and `extract` commands run on the fuzz input as the CLI would.
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzz_util.h"

static FILE *mayhem_err;
#undef stderr
#define stderr mayhem_err
#define main osafeloader_main
#include "package/utils/osafeloader/src/osafeloader.c"
#undef main
#undef stderr

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_err = fuzz_sink_init();
	return mayhem_err ? 0 : -1;
}

static int run_info(const char *path)
{
	char *argv[] = { "osafeloader", "info", (char *)path, NULL };

	return osafeloader_info(3, argv);
}

static int run_extract(const char *path, const char *part, const char *out)
{
	char *argv[] = { "osafeloader", "extract", (char *)path, "-p", (char *)part, "-o", (char *)out, NULL };

	partition_name = NULL;
	out_path = NULL;
	return osafeloader_extract(7, argv);
}

/* First partition name of the "fwup-ptn" table, or NULL. */
static const char *first_partition(const uint8_t *buf, size_t size, char *out)
{
	static const char key[] = "fwup-ptn ";
	size_t off = 0x1014, n = 0;

	if (off + sizeof(key) >= size || memcmp(buf + off, key, sizeof(key) - 1))
		return NULL;
	off += sizeof(key) - 1;
	while (off + n < size && n < 31 && buf[off + n] > ' ')
		n++;
	if (!n)
		return NULL;
	memcpy(out, buf + off, n);
	out[n] = '\0';
	return out;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *path, *out, name[40];
	size_t i;
	int ok;
	static const char *const known[] = { "os-image", "file-system", "fs-uboot", "partition-table" };

	fuzz_sink_reset();

	path = fuzz_write_tmp(data, size);
	out = fuzz_tmp_name("safeloader-out");
	if (!path || !out) {
		free(path);
		free(out);
		return -1;
	}

	/*
	 * `info` verifies the header MD5; `extract` reads the partition table without checking it, so
	 * both run on every input. The input is only rejected when the tool refuses all of it.
	 */
	ok = run_info(path) == 0;
	if (first_partition(data, size, name))
		ok |= run_extract(path, name, out) == 0;
	for (i = 0; i < sizeof(known) / sizeof(known[0]); i++)
		ok |= run_extract(path, known[i], out) == 0;

	unlink(out);
	unlink(path);
	free(path);
	free(out);
	return ok ? 0 : -1;
}
