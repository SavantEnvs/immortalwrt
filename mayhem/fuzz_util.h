#ifndef FUZZ_UTIL_H
#define FUZZ_UTIL_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>

/* Anonymous in-memory sink for the stdout/stderr noise of the code under test (no path involved);
 * truncated before every input so it stays tiny. */
static int fuzz_sink_fd = -1;

static FILE *fuzz_sink_init(void)
{
	fuzz_sink_fd = (int)syscall(SYS_memfd_create, "mayhem-sink", 0);
	if (fuzz_sink_fd < 0) {
		const char *dir = getenv("TMPDIR");
		char path[512];

		snprintf(path, sizeof(path), "%s/sink-XXXXXX", dir && *dir ? dir : "/tmp");
		fuzz_sink_fd = mkstemp(path);
		if (fuzz_sink_fd < 0)
			return NULL;
		unlink(path);
	}
	dup2(fuzz_sink_fd, 1);
	return fdopen(dup(fuzz_sink_fd), "w");
}

static void fuzz_sink_reset(void)
{
	fflush(stdout);
	if (fuzz_sink_fd >= 0 && ftruncate(fuzz_sink_fd, 0) == 0)
		lseek(fuzz_sink_fd, 0, SEEK_SET);
}

/* First line of what the code under test has printed since the last reset, or NULL if empty. */
static const char *fuzz_sink_first_line(char *buf, size_t len)
{
	ssize_t n;
	char *nl;

	fflush(stdout);
	n = pread(fuzz_sink_fd, buf, len - 1, 0);
	if (n <= 0)
		return NULL;
	buf[n] = '\0';
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return *buf ? buf : NULL;
}

/* Write the fuzz input to a fresh scratch file under $TMPDIR; returns a malloc'd path or NULL. */
static char *fuzz_write_tmp(const uint8_t *data, size_t size)
{
	const char *dir = getenv("TMPDIR");
	char *path;
	int fd;
	size_t off = 0;

	if (!dir || !*dir)
		dir = "/tmp";
	path = malloc(strlen(dir) + 32);
	if (!path)
		return NULL;
	sprintf(path, "%s/fuzz-XXXXXX", dir);
	fd = mkstemp(path);
	if (fd < 0) {
		free(path);
		return NULL;
	}
	while (off < size) {
		ssize_t w = write(fd, data + off, size - off);
		if (w <= 0) {
			close(fd);
			unlink(path);
			free(path);
			return NULL;
		}
		off += (size_t)w;
	}
	close(fd);
	return path;
}

static char *fuzz_tmp_name(const char *tag)
{
	const char *dir = getenv("TMPDIR");
	char *path;

	if (!dir || !*dir)
		dir = "/tmp";
	path = malloc(strlen(dir) + strlen(tag) + 16);
	if (path)
		sprintf(path, "%s/%s-%d", dir, tag, (int)getpid());
	return path;
}
#endif
