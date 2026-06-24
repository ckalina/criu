#include <stdint.h>
#include "maps13.h"

const char *test_doc =
	"Check CRIU skips vDSO parasite probing on anonymous RX guard pages "
	"and restores MADV_GUARD_INSTALL state";
const char *test_author = "Čestmír Kalina <ckalina@redhat.com>";

int main(int argc, char *argv[])
{
	struct testcase ctx = {
		.guard_page_idx = 0,
		.nr_pages = 3U,
		.mmap_addr = NULL,
		.mmap_prot = PROT_READ | PROT_EXEC,
		.mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS,
	};

	test_init(argc, argv);

	return do_main(argc, argv, &ctx);
}
