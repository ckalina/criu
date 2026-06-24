#ifndef ZDTM_STATIC_MAPS13_H_
#define ZDTM_STATIC_MAPS13_H_

#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "zdtmtst.h"

#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif

#ifndef MADV_GUARD_REMOVE
#define MADV_GUARD_REMOVE 103
#endif

struct testcase {
	size_t nr_pages;
	void *mmap_addr;
	int mmap_prot;
	int mmap_flags;
	int no_madvise_fallback;
	bool pre_mapped;

	int (*populate)(char *, size_t, size_t, struct testcase *);

	union {
		size_t guard_page_idx;
		size_t param1;
	};
	size_t param2;

	/*
	 * NULL means that we've got single guard page, otherwise this cb
	 * controls whether a page is a guard page
	 */
	bool (*is_guard_page)(size_t, struct testcase *);
};

static sigjmp_buf segv_jmp;
static volatile sig_atomic_t segv_armed;
static volatile sig_atomic_t segv_code;
static uintptr_t segv_expected_start;
static uintptr_t segv_expected_end;

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	uintptr_t addr = (uintptr_t)si->si_addr;

	(void)ctx;
	if (!segv_armed || addr < segv_expected_start || addr >= segv_expected_end)
		_exit(128 + sig);

	segv_code = si->si_code;
	segv_armed = 0;
	siglongjmp(segv_jmp, 1);
}

static int install_segv_handler(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		pr_perror("sigaction(SIGSEGV)");
		return -1;
	}

	return 0;
}

static bool can_read_byte(void *addr)
{
	volatile unsigned char *p = addr;
	volatile unsigned char sink;
	uintptr_t fault_addr = (uintptr_t)addr;

	segv_code = 0;

	if (sigsetjmp(segv_jmp, 1)) {
		segv_armed = 0;
		segv_expected_start = 0;
		segv_expected_end = 0;
		return false;
	}

	segv_expected_start = fault_addr;
	segv_expected_end = fault_addr + 1;
	segv_armed = 1;

	asm volatile("" : : : "memory");

	sink = *p;
	(void)sink;

	asm volatile("" : : : "memory");

	segv_armed = 0;
	segv_expected_start = 0;
	segv_expected_end = 0;
	segv_code = 0;

	return true;
}

static int check_pages(char *base, size_t ps, bool guards_installed, struct testcase *ctx)
{
	size_t i;
	bool is_guard, is_readable;

	for (i = 0; i < ctx->nr_pages; i++) {
		is_guard = ctx->is_guard_page(i, ctx);
		is_readable = can_read_byte(base + i * ps);

		if (guards_installed && is_guard && is_readable) {
			fail("guard page %zu at %p is readable", i, base + i * ps);
			return 1;
		}

		if (!guards_installed && is_guard && !is_readable) {
			fail("guard page %zu at %p is unreadable after MADV_GUARD_REMOVE, si_code=%d", i,
			     base + i * ps, (int)segv_code);
			return 1;
		}

		if (!is_readable && !is_guard) {
			fail("ordinary page %zu at %p is not readable, si_code=%d",
			     i, base + i * ps, (int)segv_code);
			return 1;
		}
	}

	return 0;
}

#define advice_str(X) ((X) == MADV_GUARD_INSTALL) ? "MADV_GUARD_INSTALL" : "MADV_GUARD_REMOVE"

static int apply_advice(void *base, void *guard, size_t ps, size_t len,
			int prot, int advice, bool can_skip, bool no_fallback)
{
	int err;

	if (madvise(guard, ps, advice) == 0)
		return 0;

	err = errno;
	if (can_skip && (err == ENOSYS || (err == EINVAL && no_fallback))) {
		skip("madvise(%s): errno=%d (%s)", advice_str(advice), err,
		     strerror(err));
		return -1;
	}

	if (err != EINVAL || no_fallback) {
		pr_perror("madvise(%s)", advice_str(advice));
		return 1;
	}

	/* Retry madvise on PROT_READ | PROT_WRITE (older kernels). */
	test_msg("madvise(%s): errno=%d (%s), retry on RW\n",
		 advice_str(advice), err, strerror(err));

	if (mprotect(base, len, PROT_READ | PROT_WRITE) < 0) {
		pr_perror("mprotect(PROT_READ|PROT_WRITE)");
		return 1;
	}

	if (madvise(guard, ps, advice) < 0) {
		err = errno;
		if (can_skip && err == EINVAL) {
			skip("madvise(%s): errno=%d (%s)", advice_str(advice),
			     err, strerror(err));
			return -1;
		}
		pr_perror("madvise(%s)", advice_str(advice));
		return 1;
	}

	if (mprotect(base, len, prot) < 0) {
		pr_perror("mprotect(%d)", prot);
		return 1;
	}

	return 0;
}

static bool single_guard_page(size_t page_idx, struct testcase *ctx)
{
	return page_idx == ctx->guard_page_idx;
}

int do_main(int argc, char *argv[], struct testcase *ctx)
{
	int ret;
	void *p;
	char *base;
	size_t ps, len, i, nr_guards = 0;
	long page_size;

	/* setup testcase default values */

	if (!ctx->is_guard_page)
		ctx->is_guard_page = single_guard_page;

	/* validate that testcase has admissible values */

	if (ctx->guard_page_idx >= ctx->nr_pages) {
		fail("guard page outside mapping");
		return 1;
	}

	for (i = 0; i < ctx->nr_pages; i++)
		nr_guards += ctx->is_guard_page(i, ctx);

	if (!nr_guards || nr_guards == ctx->nr_pages) {
		fail("need at least one guard and one ordinary page");
		return 1;
	}

	/* test case setup */

	if ((page_size = sysconf(_SC_PAGESIZE)) < 0) {
		pr_perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	ps = (size_t)page_size;
	len = ctx->nr_pages * ps;

	test_msg("pagesize %zu, pages: %zu, guard pages %zu\n",
		 ps, ctx->nr_pages, nr_guards);

	if (ctx->pre_mapped) {
		p = ctx->mmap_addr;
		goto skip_mmap;
	}

	p = mmap(ctx->mmap_addr, len, ctx->mmap_prot, ctx->mmap_flags, -1, 0);
	if (p == MAP_FAILED) {
		int err = errno;
		switch (err) {
		case EEXIST:
		case EINVAL:
		case EPERM:
		case EACCES:
			skip("mmap(%d,%d): errno=%d (%s)", ctx->mmap_prot,
			     ctx->mmap_flags, err, strerror(err));
			return 0;
		default:
			break;
		}
		pr_perror("mmap(%d,%d)", ctx->mmap_prot, ctx->mmap_flags);
		return 1;
	}

skip_mmap:
	base = p;
	test_msg("mmap area: %p-%p\n", base, base + len);

	if (!ctx->pre_mapped && ctx->populate && (ret = ctx->populate(base, ps, len, ctx)))
		return ret > 0;

	if (install_segv_handler())
		return 1;

	/* setup guard pages */

	for (i = 0; i < ctx->nr_pages; i++) {
		if (!ctx->is_guard_page(i, ctx))
			continue;
		ret = apply_advice(base, base + i * ps, ps, len, ctx->mmap_prot,
				   MADV_GUARD_INSTALL, true, ctx->no_madvise_fallback);
		if (ret)
			return ret > 0;
	}

	if (check_pages(base, ps, true, ctx))
		return 1;

	test_daemon();
	test_waitsig();

	if (check_pages(base, ps, true, ctx))
		return 1;

	for (i = 0; i < ctx->nr_pages; i++) {
		if (!ctx->is_guard_page(i, ctx))
			continue;
		ret = apply_advice(base, base + i * ps, ps, len, ctx->mmap_prot,
				   MADV_GUARD_REMOVE, false, ctx->no_madvise_fallback);
		if (ret)
			return ret > 0;
	}

	if (check_pages(base, ps, false, ctx))
		return 1;

	if (munmap(base, len)) {
		pr_perror("munmap");
		return 1;
	}

	pass();

	return 0;
}

#endif
