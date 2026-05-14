// SPDX-License-Identifier: GPL-2.0
/*
 * test_redirect — minimal userspace smoke test for redirfs-lite.
 *
 * Procedure:
 *   1. Create /tmp/rfl_src and /tmp/rfl_dst with distinct contents.
 *   2. Install rule: /tmp/rfl_src -> /tmp/rfl_dst.
 *   3. open("/tmp/rfl_src") and read — should see rfl_dst's content.
 *   4. readlink("/proc/self/fd/N") — should see the virtual src path.
 *
 * Note: run as root or whichever UID matches the rule.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define SRC "/tmp/rfl_src"
#define DST "/tmp/rfl_dst"
#define RULES "/proc/redirfs/rules"

static int write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, content, strlen(content));
	close(fd);
	return n == (ssize_t)strlen(content) ? 0 : -1;
}

static int install_rule(const char *src, const char *dst)
{
	int fd = open(RULES, O_WRONLY);
	char buf[512];
	int n;

	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", RULES, strerror(errno));
		return -1;
	}
	n = snprintf(buf, sizeof buf, "add %s %s * *\n", src, dst);
	if (write(fd, buf, n) != n) {
		fprintf(stderr, "write rule: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int main(void)
{
	char buf[64], link[256];
	int fd, n;
	ssize_t r;

	if (write_file(SRC, "source content\n") < 0 ||
	    write_file(DST, "destination content\n") < 0) {
		perror("setup files");
		return 1;
	}
	if (install_rule(SRC, DST) < 0)
		return 2;

	fd = open(SRC, O_RDONLY);
	if (fd < 0) {
		perror("open src");
		return 3;
	}
	r = read(fd, buf, sizeof buf - 1);
	if (r < 0) {
		perror("read");
		close(fd);
		return 4;
	}
	buf[r] = '\0';
	printf("read from %s: %s", SRC, buf);

	n = snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
	r = readlink(link, buf, sizeof buf - 1);
	if (r > 0) {
		buf[r] = '\0';
		printf("readlink %s -> %s\n", link, buf);
	}
	close(fd);

	if (strstr(buf, "destination") || !strcmp(buf, DST)) {
		fprintf(stderr, "FAIL: virtual path leaked real dst\n");
		return 5;
	}
	if (!strstr(buf, "source content")) {
		fprintf(stderr, "FAIL: read returned %s, expected destination "
				"content (redirected)\n", buf);
	}
	puts("ok");
	return 0;
}
