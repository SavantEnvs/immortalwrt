/*
 * In-process harness for ImmortalWrt's fritz_tffs_read tool (AVM Fritz!Box TFFS name/value store).
 * The tool's own source is compiled into this file; its main() is driven with the same -l / -a / -n
 * invocations (plus -b byte swapping) the CLI accepts, on the fuzz input written to a scratch file.
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
#define main fritz_tffs_main
#include "package/utils/fritz-tools/src/fritz_tffs_read.c"
#undef main
#undef stderr

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_err = fuzz_sink_init();
	return mayhem_err ? 0 : -1;
}

static int run(const char *path, const char *a, const char *b, const char *c)
{
	char *argv[8];
	int argc = 0;

	argv[argc++] = "fritz_tffs_read";
	if (a)
		argv[argc++] = (char *)a;
	if (b)
		argv[argc++] = (char *)b;
	if (c)
		argv[argc++] = (char *)c;
	argv[argc++] = "-i";
	argv[argc++] = (char *)path;
	argv[argc] = NULL;

	optind = 0;
	input_file = NULL;
	tffs_size = 0;
	name_filter = NULL;
	show_all = false;
	print_all_key_names = false;
	swap_bytes = false;
	return fritz_tffs_main(argc, argv);
}

/* -a and -n for one byte order; the key to look up is the first one `-l` listed, plus a fixed one. */
static void read_values(const char *path, const char *swap)
{
	char first[256];
	const char *key;

	run(path, swap, "-a", NULL);
	run(path, swap, "-n", "firmware_version");
	fuzz_sink_reset();
	run(path, swap, "-l", NULL);
	key = fuzz_sink_first_line(first, sizeof(first));
	if (key)
		run(path, swap, "-n", key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *path;
	int le, be;

	fuzz_sink_reset();
	/* A TFFS image is a run of struct tffs_entry_header {id, len} + payload, and main() reads the first
	 * header at offset 0 unconditionally (find_entry/parse_entry): an input too short to hold even one
	 * header is not an image. Longer inputs with bad lengths are not skipped, they reach the overreads. */
	if (size < sizeof(struct tffs_entry_header))
		return -1;

	path = fuzz_write_tmp(data, size);
	if (!path)
		return -1;

	le = run(path, NULL, "-l", NULL) == 0;
	if (le)
		read_values(path, NULL);
	be = run(path, "-b", "-l", NULL) == 0;
	if (be)
		read_values(path, "-b");

	unlink(path);
	free(path);
	return le || be ? 0 : -1;
}
