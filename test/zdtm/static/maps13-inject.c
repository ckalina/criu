/*
 * Guarded executable VMAs selected for parasite injection.
 *
 * get_exec_start() returns the first sufficiently-large executable VMA
 * without checking guard ranges. If that VMA's first page is guarded,
 * compel_execute_syscall() tries to ptrace-read/write a guard page and
 * the infection fails.
 *
 * This test maps an anonymous RX region below the binary's .text, guards
 * its first page, then attempts C/R.
 *
 * We need our anonymous RX mapping to appear *before* the binary's own
 * .text in address order so that get_exec_start() picks it first. Place it
 * immediately below the process's lowest existing mapping instead of relying
 * on an architecture-specific static binary load address.
 *
 * MAP_FIXED_NOREPLACE makes the attempt safe; if that range is unavailable,
 * skip rather than clobbering it.
 */

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#include "maps13.h"

const char *test_doc =
	"Guarded first page of lowest exec VMA blocks parasite injection";
const char *test_author = "Čestmír Kalina <ckalina@redhat.com>";

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static void *find_inject_addr(size_t len)
{
	unsigned long first_start;
	FILE *maps;

	maps = fopen("/proc/self/maps", "r");
	if (!maps)
		return NULL;

	if (fscanf(maps, "%lx-", &first_start) != 1)
		first_start = 0;
	fclose(maps);

	if (first_start <= len)
		return NULL;

	return (void *)(uintptr_t)(first_start - len);
}

int main(int argc, char *argv[])
{
	struct testcase ctx = {
		.guard_page_idx = 0U,
		.nr_pages = 2U,
		.mmap_prot = PROT_READ | PROT_EXEC,
		.mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE
	};
	long page_size;

	test_init(argc, argv);

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		pr_perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	ctx.mmap_addr = find_inject_addr(ctx.nr_pages * (size_t)page_size);
	if (!ctx.mmap_addr) {
		skip("no address range below the process mappings");
		return 0;
	}

	return do_main(argc, argv, &ctx);
}
