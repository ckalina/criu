/*
 * maps13-sym does not need a real vDSO. It needs an anonymous RX mapping
 * which looks enough like a native ET_DYN ELF image that CRIU's forced
 * VDSO_CHECK_SYMS path would start parsing it.
 *
 * All cheap identification data lives on page 0, while the dynamic section
 * is placed on the guarded page.
 *
 * Without mocking up an image criu terminates early with 'Invalid ELF magic'
 * and we don't truly test the VDSO_CHECK_SYMS discovery that we mask.
 *
 * Fake vDSO candidate layout:
 *
 * Page 0: ELF header, PT_LOAD, PT_DYNAMIC program headers.
 *         This page must stay readable for criu to get past first-page
 *         candidate checks.
 *
 * Page 1: PT_DYNAMIC payload. This is the guarded page.
 *         STRTAB, SYMTAB, STRSZ, SYMENT, HASH, NULL
 *
 * Page 2: Zeroed string/symbol/hash storage referenced by DT_* entries.
 *
 */

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#include "zdtmtst.h"

#include "maps13.h"

const char *test_doc =
	"Check CRIU skips guarded vDSO symbol-table probing on anonymous RX "
	"candidate.";
const char *test_author = "Čestmír Kalina <ckalina@redhat.com>";

#if UINTPTR_MAX == UINT64_MAX
#define TEST_ELF_CLASS ELFCLASS64
typedef Elf64_Ehdr ehdr_t;
typedef Elf64_Phdr phdr_t;
typedef Elf64_Dyn dyn_t;
typedef Elf64_Sym sym_t;
typedef Elf64_Word word_t;
#else
#define TEST_ELF_CLASS ELFCLASS32
typedef Elf32_Ehdr ehdr_t;
typedef Elf32_Phdr phdr_t;
typedef Elf32_Dyn dyn_t;
typedef Elf32_Sym sym_t;
typedef Elf32_Word word_t;
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BORD ELFDATA2MSB
#else
#define BORD ELFDATA2LSB
#endif

#if defined(__x86_64__)
#define ELF_EM EM_X86_64
#elif defined(__i386__)
#define ELF_EM EM_386
#elif defined(__aarch64__)
#define ELF_EM EM_AARCH64
#elif defined(__arm__)
#define ELF_EM EM_ARM
#elif defined(__powerpc64__)
#define ELF_EM EM_PPC64
#elif defined(__s390x__)
#define ELF_EM EM_S390
#elif defined(__riscv)
#define ELF_EM EM_RISCV
#elif defined(__mips__)
#define ELF_EM EM_MIPS
#elif defined(__loongarch64)
#define ELF_EM EM_LOONGARCH
#else
#define ELF_EM EM_NONE
#endif

static int fake_vdso_candidate(char *base, size_t ps, size_t len, struct testcase *ctx)
{
	ehdr_t *ehdr = (void *)base;
	phdr_t *phdr = (void *)(base + sizeof(*ehdr));

	size_t dyn_off = ctx->guard_page_idx * ps;
	dyn_t *dyn = (void *)(base + dyn_off);

	size_t strtab_off = 2 * ps;
	size_t symtab_off = 2 * ps + 0x40;
	size_t hash_off = 2 * ps + 0x80;
	word_t *hash;

	if (ctx->guard_page_idx == 0) {
		fail("fake vDSO symtable candidate needs an unguarded first page");
		return -1;
	}

	if (sizeof(*ehdr) + 2 * sizeof(*phdr) > ps ||
	    dyn_off + 6 * sizeof(*dyn) > len ||
	    hash_off + 4 * sizeof(*hash) > len) {
		fail("fake vDSO layout does not fit in the test mapping");
		return -1;
	}

	if (mprotect(base, len, PROT_READ | PROT_WRITE) < 0) {
		pr_perror("mprotect(PROT_READ|PROT_WRITE)");
		return -1;
	}

	memset(base, 0, len);

	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = TEST_ELF_CLASS;
	ehdr->e_ident[EI_DATA] = BORD;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr->e_type = ET_DYN;
	ehdr->e_machine = ELF_EM;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_phoff = sizeof(*ehdr);
	ehdr->e_ehsize = sizeof(*ehdr);
	ehdr->e_phentsize = sizeof(*phdr);
	ehdr->e_phnum = 2;

	phdr[0].p_type = PT_LOAD;
	phdr[0].p_flags = PF_R | PF_X;
	phdr[0].p_offset = 0;
	phdr[0].p_vaddr = 0;
	phdr[0].p_filesz = len;
	phdr[0].p_memsz = len;
	phdr[0].p_align = ps;

	phdr[1].p_type = PT_DYNAMIC;
	phdr[1].p_flags = PF_R;
	phdr[1].p_offset = dyn_off;
	phdr[1].p_vaddr = dyn_off;
	phdr[1].p_filesz = 6 * sizeof(*dyn);
	phdr[1].p_memsz = phdr[1].p_filesz;
	phdr[1].p_align = sizeof(*dyn);

	dyn[0].d_tag = DT_STRTAB;
	dyn[0].d_un.d_ptr = strtab_off;
	dyn[1].d_tag = DT_SYMTAB;
	dyn[1].d_un.d_ptr = symtab_off;
	dyn[2].d_tag = DT_STRSZ;
	dyn[2].d_un.d_val = 1;
	dyn[3].d_tag = DT_SYMENT;
	dyn[3].d_un.d_val = sizeof(sym_t);
	dyn[4].d_tag = DT_HASH;
	dyn[4].d_un.d_ptr = hash_off;
	dyn[5].d_tag = DT_NULL;

	hash = (void *)(base + hash_off);
	hash[0] = 1; /* nbucket */
	hash[1] = 1; /* nchain */
	hash[2] = 0; /* bucket[0] */
	hash[3] = 0; /* chain[0] */

	if (mprotect(base, len, PROT_READ | PROT_EXEC) < 0) {
		pr_perror("mprotect(PROT_READ|PROT_EXEC)");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct testcase ctx = {
		.guard_page_idx = 1U,
		.nr_pages = 3U,
		.mmap_addr = NULL,
		.mmap_prot = PROT_READ | PROT_EXEC,
		.mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS,
		.populate = fake_vdso_candidate
	};

	test_init(argc, argv);

	return do_main(argc, argv, &ctx);
}
