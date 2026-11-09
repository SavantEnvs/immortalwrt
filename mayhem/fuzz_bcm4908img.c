/*
 * In-process harness for ImmortalWrt's bcm4908img tool (BCM4908 firmware image: vendor header, cferom,
 * JFFS2 bootfs, UBI rootfs, CRC32 tail). The tool's own sources are compiled into this file so its static
 * `create`, `info`, `extract` and `bootfs ls|mv` commands run on the fuzz input exactly as the CLI would.
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
#define main bcm4908img_main
#include "package/utils/bcm4908img/src/bcm4908img.c"
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
	char *argv[] = { "bcm4908img", "info", "-i", (char *)path, NULL };

	optind = 2;
	return bcm4908img_info(4, argv);
}

static int run_extract(const char *path, const char *type)
{
	char *argv[] = { "bcm4908img", "extract", "-i", (char *)path, "-t", (char *)type, NULL };

	optind = 2;
	return bcm4908img_extract(6, argv);
}

static int run_bootfs(const char *path, const char *cmd, const char *a, const char *b)
{
	char *argv[] = { "bcm4908img", "bootfs", "-i", (char *)path, (char *)cmd, (char *)a, (char *)b, NULL };

	optind = 2;
	return bcm4908img_bootfs(a ? 7 : 5, argv);
}

/* Name of the first JFFS2 directory entry of the bootfs, or NULL. */
static const char *first_dirent_name(const uint8_t *buf, size_t size, size_t offset, char *out)
{
	int hops;

	for (hops = 0; hops < 64 && offset + sizeof(struct jffs2_raw_dirent) <= size; hops++) {
		const struct jffs2_raw_dirent *d = (const void *)(buf + offset);
		uint32_t totlen = je32_to_cpu(d->totlen);

		if (je16_to_cpu(d->magic) != JFFS2_MAGIC_BITMASK)
			return NULL;
		if (je16_to_cpu(d->nodetype) == JFFS2_NODETYPE_DIRENT) {
			size_t n = d->nsize;

			if (!n || n > 200 ||
			    offset + offsetof(struct jffs2_raw_dirent, name) + n > size)
				return NULL;
			memcpy(out, buf + offset + offsetof(struct jffs2_raw_dirent, name), n);
			out[n] = '\0';
			return out;
		}
		if (!totlen)
			return NULL;
		offset += (totlen + 3) & ~3u;
	}
	return NULL;
}

static int run_create(const char *out, const char *payload)
{
	char *argv[] = { "bcm4908img", "create", (char *)out, "-f", (char *)payload, NULL };

	return bcm4908img_create(5, argv);
}

/*
 * Run the tool's commands on one image file. The tool's own parser decides whether it is an image (layout
 * and CRC32); returns 1 if it accepted it and the commands ran, 0 if it refused.
 */
static int run_image(const char *path, const uint8_t *data, size_t size)
{
	static const char *const types[] = { "cferom", "bootfs", "rootfs", "firmware" };
	struct bcm4908img_info info;
	char name[256], renamed[256];
	FILE *fp;
	int err, i;

	fp = fopen(path, "r");
	if (!fp)
		return 0;
	err = bcm4908img_parse(fp, &info);
	fclose(fp);
	if (err)
		return 0;

	run_info(path);
	for (i = 0; i < 4; i++)
		run_extract(path, types[i]);
	run_bootfs(path, "ls", NULL, NULL);
	if (first_dirent_name(data, size, info.bootfs_offset, name)) {
		size_t n = strlen(name);

		memcpy(renamed, name, n + 1);
		renamed[0] = renamed[0] == 'x' ? 'y' : 'x';
		run_bootfs(path, "mv", name, renamed);
		run_bootfs(path, "ls", NULL, NULL);
	}
	return 1;
}

/*
 * The input is used two ways, both through the tool as shipped:
 *  - as a finished image, exactly what `bcm4908img info|extract|bootfs -i <file>` would read;
 *  - as the payload of `bcm4908img create <out> -f <file>`, which appends the tail with the CRC32 it
 *    computes itself, and then the same commands read that image.
 * The CRC32 is never written by the harness, so every saved input replays with the real tool: the first
 * way as `info -i <file>`, the second as `create out -f <file>` followed by `info -i out`.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char *path, *built;
	int ok;

	fuzz_sink_reset();

	path = fuzz_write_tmp(data, size);
	built = fuzz_tmp_name("bcm4908img-built");
	if (!path || !built) {
		free(path);
		free(built);
		return -1;
	}

	ok = run_image(path, data, size);
	if (run_create(built, path) == 0)
		ok |= run_image(built, data, size);

	unlink(built);
	unlink(path);
	free(built);
	free(path);
	return ok ? 0 : -1;
}
