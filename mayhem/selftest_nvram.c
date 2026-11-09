/* Known-answer test for libnvram: read a fixture, edit it, commit and read it back. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../package/utils/nvram/src/nvram.h"

extern size_t nvram_part_size;

static void show(nvram_handle_t *h, const char *name)
{
	char *v = nvram_get(h, name);

	printf("%s=%s\n", name, v ? v : "(null)");
}

int main(int argc, char **argv)
{
	static const char *keys[] = { "boardtype", "boardnum", "et0macaddr", "lan_ipaddr", "wl0_ssid", "sdram_init" };
	nvram_handle_t *h;
	char tmp[] = "/tmp/nvram-selftest-XXXXXX";
	char cmd[512];
	size_t i;

	if (argc < 2)
		return 2;
	nvram_part_size = 0x10000;

	h = nvram_open(argv[1], NVRAM_RO);
	if (!h)
		return 3;
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++)
		show(h, keys[i]);
	show(h, "nothere");
	nvram_close(h);

	close(mkstemp(tmp));
	snprintf(cmd, sizeof(cmd), "cp '%s' '%s'", argv[1], tmp);
	if (system(cmd))
		return 4;
	h = nvram_open(tmp, NVRAM_RW);
	if (!h)
		return 5;
	nvram_set(h, "wl0_ssid", "Edited-SSID");
	nvram_set(h, "newvar", "42");
	nvram_unset(h, "boardnum");
	if (nvram_commit(h))
		return 6;
	nvram_close(h);

	h = nvram_open(tmp, NVRAM_RO);
	if (!h)
		return 7;
	printf("after:\n");
	show(h, "wl0_ssid");
	show(h, "newvar");
	show(h, "boardnum");
	show(h, "lan_ipaddr");
	nvram_close(h);
	unlink(tmp);
	return 0;
}
