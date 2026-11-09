/* In-process harness for ImmortalWrt's libnvram (Broadcom NVRAM partition image parser). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "package/utils/nvram/src/nvram.h"
#include "fuzz_util.h"

/* libnvram's partition size; nvram_find_mtd() fills it from /proc/mtd, and nvram_open() on a file refuses
 * to run while it is 0. Set once: nothing in nvram_open() or the calls below changes it for a file. */
extern size_t nvram_part_size;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	nvram_part_size = 0x10000;
	return 0;
}

struct pair {
	char *name;
	char *value;
};

/* Copy every name/value out of a getall() list (it shares the live value pointers) and free the list. */
static struct pair *snapshot(nvram_tuple_t *all, size_t *count)
{
	nvram_tuple_t *t, *next;
	struct pair *p;
	size_t n = 0, i = 0;

	for (t = all; t; t = t->next)
		n++;
	p = calloc(n ? n : 1, sizeof(*p));
	for (t = all; t; t = next) {
		next = t->next;
		if (p) {
			p[i].name = strdup(t->name);
			p[i].value = strdup(t->value ? t->value : "");
			i++;
		}
		free(t);
	}
	*count = p ? n : 0;
	return p;
}

static void snapshot_free(struct pair *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		free(p[i].name);
		free(p[i].value);
	}
	free(p);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	nvram_handle_t *h;
	nvram_tuple_t *t, *next, *all;
	struct pair *pairs;
	char *path, value[256];
	size_t i, n;
	int opened = 0;

	path = fuzz_write_tmp(data, size);
	if (!path)
		return -1;

	/* read-only view: enumerate and look every variable up again */
	h = nvram_open(path, NVRAM_RO);
	if (h) {
		opened = 1;
		all = nvram_getall(h);
		for (t = all; t; t = next) {
			next = t->next;
			if (nvram_get(h, t->name) != t->value)
				abort();
			free(t);
		}
		nvram_close(h);
	}

	/* read-write view: edit and regenerate the partition */
	h = nvram_open(path, NVRAM_RW);
	if (h) {
		opened = 1;
		memset(value, 'v', sizeof(value) - 1);
		value[sizeof(value) - 1] = 0;
		pairs = snapshot(nvram_getall(h), &n);
		for (i = 0; i < n; i++) {
			nvram_set(h, "mayhem_extra", pairs[i].value);
			nvram_set(h, pairs[i].name, value);
		}
		snapshot_free(pairs, n);
		nvram_unset(h, "mayhem_extra");
		nvram_set(h, "mayhem_new", "1");
		nvram_commit(h);
		all = nvram_getall(h);
		for (t = all; t; t = next) {
			next = t->next;
			free(t);
		}
		nvram_close(h);
	}

	unlink(path);
	free(path);
	return opened ? 0 : -1;
}
