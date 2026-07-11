/*
 * CRIU asks PAGEMAP_SCAN for 1000 ranges at a time. Some kernels use a
 * smaller internal scan buffer. They can flush that buffer, continue the
 * same ioctl, return later ranges, but leave walk_end at the first internal
 * buffer boundary.
 *
 * Create 999 isolated guard ranges so they fit in CRIU's result vector but
 * exceed the common 512-entry internal buffer. The populate callback proves
 * two things before the normal C/R test starts:
 *
 *   1. the first ioctl returned a range ending after raw walk_end;
 *   2. an old-style second ioctl starting at raw walk_end repeats part of
 *      the first result.
 *
 * It then removes the guards. maps13.h installs the exact same layout again
 * and performs the normal checkpoint/restore validation.
 */
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "maps13.h"

#ifndef PAGEMAP_SCAN
struct page_region {
	uint64_t start;
	uint64_t end;
	uint64_t categories;
};

struct pm_scan_arg {
	uint64_t size;
	uint64_t flags;
	uint64_t start;
	uint64_t end;
	uint64_t walk_end;
	uint64_t vec;
	uint64_t vec_len;
	uint64_t max_pages;
	uint64_t category_inverted;
	uint64_t category_mask;
	uint64_t category_anyof_mask;
	uint64_t return_mask;
};

#define PAGEMAP_SCAN _IOWR('f', 16, struct pm_scan_arg)
#endif

#ifndef PAGE_IS_GUARD
#define PAGE_IS_GUARD (1ULL << 8)
#endif

#define SCAN_VEC_LEN 1000U
#define NR_GUARDS (SCAN_VEC_LEN - 1U)
#define GUARD_STRIDE 2U
#define FIRST_GUARD_PAGE 1U
#define NR_PAGES (NR_GUARDS * GUARD_STRIDE)
#define SPLIT_PAGE (NR_PAGES / 2U)

const char *test_doc =
	"Check MADV_GUARD_INSTALL collection across a PAGEMAP_SCAN buffer boundary";
const char *test_author = "Čestmír Kalina <ckalina@redhat.com>";

static bool is_guard_page(size_t page, struct testcase *ctx)
{
	size_t guard;

	(void)ctx;
	if (page < FIRST_GUARD_PAGE)
		return false;

	page -= FIRST_GUARD_PAGE;
	if (page % GUARD_STRIDE)
		return false;

	guard = page / GUARD_STRIDE;
	return guard < NR_GUARDS;
}

static int change_guards(char *base, size_t ps, int advice, size_t nr_guards)
{
	size_t guard;

	for (guard = 0; guard < nr_guards; guard++) {
		size_t page = FIRST_GUARD_PAGE + guard * GUARD_STRIDE;

		if (madvise(base + page * ps, ps, advice)) {
			pr_perror("madvise(%s) page=%zu",
				  advice == MADV_GUARD_INSTALL ?
				  "MADV_GUARD_INSTALL" : "MADV_GUARD_REMOVE",
				  page);
			return -1;
		}
	}

	return 0;
}

/*
 * Returns 1 when stale walk_end and an overlapping second scan are observed,
 * 0 when this kernel does not exhibit the behaviour, and -1 on test failure.
 */
static int probe_stale_walk_end(uintptr_t start, uintptr_t end)
{
	struct page_region *regs = NULL;
	uint64_t first_last_start, max_returned_end, raw_walk_end;
	long regs_len;
	int fd = -1;
	int i, ret = -1;

	struct pm_scan_arg args = {
		.size = sizeof(struct pm_scan_arg),
		.flags = 0,
		.start = start,
		.end = end,
		.walk_end = 0,
		.vec_len = SCAN_VEC_LEN,
		.max_pages = 0,
		.category_mask = PAGE_IS_GUARD,
		.return_mask = PAGE_IS_GUARD,
	};

	fd = open("/proc/self/pagemap", O_RDONLY);
	if (fd < 0) {
		pr_perror("open(/proc/self/pagemap)");
		goto out;
	}

	regs = malloc(args.vec_len * sizeof(*regs));
	if (!regs) {
		fail("cannot allocate PAGEMAP_SCAN vector");
		goto out;
	}
	args.vec = (uintptr_t)regs;

	regs_len = ioctl(fd, PAGEMAP_SCAN, &args);
	if (regs_len < 0) {
		pr_perror("PAGEMAP_SCAN call 1");
		goto out;
	}
	if (!regs_len || regs_len > SCAN_VEC_LEN) {
		fail("PAGEMAP_SCAN call 1 returned invalid range count %ld",
		     regs_len);
		goto out;
	}

	raw_walk_end = args.walk_end;
	if (raw_walk_end < start || raw_walk_end > end) {
		fail("PAGEMAP_SCAN call 1 returned invalid walk_end=%" PRIx64,
		     raw_walk_end);
		goto out;
	}
	max_returned_end = raw_walk_end;
	for (i = 0; i < regs_len; i++) {
		if (!(regs[i].categories & PAGE_IS_GUARD) ||
		    regs[i].start >= regs[i].end ||
		    regs[i].start < start || regs[i].end > end) {
			fail("invalid PAGEMAP_SCAN range %" PRIx64 "-%" PRIx64,
			     (uint64_t)regs[i].start, (uint64_t)regs[i].end);
			goto out;
		}
		if (i && regs[i].start < regs[i - 1].start) {
			fail("PAGEMAP_SCAN call 1 is unordered at %d", i);
			goto out;
		}
		if (regs[i].end > max_returned_end)
			max_returned_end = regs[i].end;
	}

	first_last_start = regs[regs_len - 1].start;
	test_msg("PAGEMAP_SCAN call=1 start=%" PRIxPTR
		 " raw_walk_end=%" PRIx64 " max_returned_end=%" PRIx64
		 " nr=%ld\n",
		 start, raw_walk_end, max_returned_end, regs_len);

	if (raw_walk_end >= max_returned_end) {
		ret = 0;
		goto out;
	}

	/* Emulate the old collector's second userspace ioctl exactly. */
	args.start = raw_walk_end;
	regs_len = ioctl(fd, PAGEMAP_SCAN, &args);
	if (regs_len < 0) {
		pr_perror("PAGEMAP_SCAN call 2");
		goto out;
	}
	if (!regs_len || regs_len > SCAN_VEC_LEN) {
		fail("stale walk_end produced invalid second range count %ld",
		     regs_len);
		goto out;
	}
	if (!(regs[0].categories & PAGE_IS_GUARD) ||
	    regs[0].start >= regs[0].end ||
	    regs[0].start < raw_walk_end || regs[0].end > end) {
		fail("invalid first range from PAGEMAP_SCAN call 2");
		goto out;
	}

	test_msg("PAGEMAP_SCAN call=2 start=%" PRIx64
		 " walk_end=%" PRIx64 " first=%" PRIx64
		 " first_call_last=%" PRIx64 " first_call_max_end=%" PRIx64
		 " nr=%ld\n",
		 raw_walk_end, (uint64_t)args.walk_end,
		 (uint64_t)regs[0].start,
		 first_last_start, max_returned_end, regs_len);

	if (regs[0].start >= max_returned_end) {
		fail("second PAGEMAP_SCAN did not repeat the first result: "
		     "first=%" PRIx64 " prior_end=%" PRIx64,
		     (uint64_t)regs[0].start, max_returned_end);
		goto out;
	}

	if (regs[0].start < first_last_start)
		test_msg("second ioctl causes the old strict backwards-order check\n");
	else
		test_msg("second ioctl repeats the final first-call range\n");

	ret = 1;
out:
	free(regs);
	if (fd >= 0)
		close(fd);
	return ret;
}

static int prepare_layout(char *base, size_t ps, size_t len,
			  struct testcase *ctx)
{
	size_t installed = 0;
	int probe;
	int ret = 1;

	if (len != NR_PAGES * ps || ctx->nr_pages != NR_PAGES ||
	    !is_guard_page(SPLIT_PAGE, ctx)) {
		fail("invalid sparse-guard layout");
		return 1;
	}

	/* Keep two distinct VMAs and guard the first page of the second one. */
	if (mprotect(base + SPLIT_PAGE * ps,
		     len - SPLIT_PAGE * ps, PROT_READ)) {
		pr_perror("mprotect(second VMA, PROT_READ)");
		return 1;
	}

	for (installed = 0; installed < NR_GUARDS; installed++) {
		size_t page = FIRST_GUARD_PAGE + installed * GUARD_STRIDE;

		if (madvise(base + page * ps, ps, MADV_GUARD_INSTALL)) {
			pr_perror("madvise(MADV_GUARD_INSTALL) page=%zu", page);
			goto remove;
		}
	}

	probe = probe_stale_walk_end((uintptr_t)base, (uintptr_t)base + len);
	if (probe < 0)
		goto remove;

	ret = probe ? 0 : -1;
remove:
	if (change_guards(base, ps, MADV_GUARD_REMOVE, installed))
		return 1;

	if (ret < 0)
		skip("kernel does not return ranges beyond raw PAGEMAP_SCAN walk_end");

	return ret;
}

int main(int argc, char *argv[])
{
	struct testcase ctx = {
		.nr_pages = NR_PAGES,
		.mmap_addr = NULL,
		.mmap_prot = PROT_READ | PROT_WRITE,
		.mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS,
		.no_madvise_fallback = 1,
		.populate = prepare_layout,
		.is_guard_page = is_guard_page,
	};

	test_init(argc, argv);

	return do_main(argc, argv, &ctx);
}
