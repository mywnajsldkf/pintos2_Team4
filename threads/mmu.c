#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "intrinsic.h"

// mmu(memory management unit): 컴퓨터의 가상 메모리 시스템 관리를 담당하는 하드웨어 구성 요소인 메모리 관리 장치
// pgdir_walk, pdpe_walk, pml4e_walk: 서로 다른 레벨에서 페이지 테이블을 순회하여 주어진 페이지 테이블 항목을 조회하거나 생성하는데 사용된다.
static uint64_t *
pgdir_walk (uint64_t *pdp, const uint64_t va, int create) {
	int idx = PDX (va);
	if (pdp) {
		uint64_t *pte = (uint64_t *) pdp[idx];
		if (!((uint64_t) pte & PTE_P)) {
			if (create) {
				uint64_t *new_page = palloc_get_page (PAL_ZERO);
				if (new_page)
					pdp[idx] = vtop (new_page) | PTE_U | PTE_W | PTE_P;
				else
					return NULL;
			} else
				return NULL;
		}
		return (uint64_t *) ptov (PTE_ADDR (pdp[idx]) + 8 * PTX (va));
	}
	return NULL;
}

static uint64_t *
pdpe_walk (uint64_t *pdpe, const uint64_t va, int create) {
	uint64_t *pte = NULL;
	int idx = PDPE (va);
	int allocated = 0;
	if (pdpe) {
		uint64_t *pde = (uint64_t *) pdpe[idx];
		if (!((uint64_t) pde & PTE_P)) {
			if (create) {
				uint64_t *new_page = palloc_get_page (PAL_ZERO);
				if (new_page) {
					pdpe[idx] = vtop (new_page) | PTE_U | PTE_W | PTE_P;
					allocated = 1;
				} else
					return NULL;
			} else
				return NULL;
		}
		pte = pgdir_walk (ptov (PTE_ADDR (pdpe[idx])), va, create);
	}
	if (pte == NULL && allocated) {
		palloc_free_page ((void *) ptov (PTE_ADDR (pdpe[idx])));
		pdpe[idx] = 0;
	}
	return pte;
}

/* Returns the address of the page table entry for virtual
 * address VADDR in page map level 4, pml4.
 * If PML4E does not have a page table for VADDR, behavior depends
 * on CREATE.  If CREATE is true, then a new page table is
 * created and a pointer into it is returned.  Otherwise, a null
 * pointer is returned. */
uint64_t *
pml4e_walk (uint64_t *pml4e, const uint64_t va, int create) {
	uint64_t *pte = NULL;
	int idx = PML4 (va);
	int allocated = 0;
	if (pml4e) {
		uint64_t *pdpe = (uint64_t *) pml4e[idx];
		if (!((uint64_t) pdpe & PTE_P)) {
			if (create) {
				uint64_t *new_page = palloc_get_page (PAL_ZERO);
				if (new_page) {
					pml4e[idx] = vtop (new_page) | PTE_U | PTE_W | PTE_P;
					allocated = 1;
				} else
					return NULL;
			} else
				return NULL;
		}
		pte = pdpe_walk (ptov (PTE_ADDR (pml4e[idx])), va, create);
	}
	if (pte == NULL && allocated) {
		palloc_free_page ((void *) ptov (PTE_ADDR (pml4e[idx])));
		pml4e[idx] = 0;
	}
	return pte;
}

/* Creates a new page map level 4 (pml4) has mappings for kernel
 * virtual addresses, but none for user virtual addresses.
 * Returns the new page directory, or a null pointer if memory
 * allocation fails. */
// 커널 가상 주소에 대한 매핑은 있지만 사용자 가상 주소에 대한 매핑은 없는 새로운 PML4 페이지 디렉토리를 생성한다.
uint64_t *
pml4_create (void) {
	uint64_t *pml4 = palloc_get_page (0);
	if (pml4)
		memcpy (pml4, base_pml4, PGSIZE);
	return pml4;
}

/**
 * pt_for_each, pgdir_for_each, pdp_for_each:
 * 페이지 테이블을 반복하고 각 페이지 테이블 항목에서 작업을 수행하는데 사용되는 유틸리티 기능
*/
static bool
pt_for_each (uint64_t *pt, pte_for_each_func *func, void *aux,
		unsigned pml4_index, unsigned pdp_index, unsigned pdx_index) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pte = &pt[i];
		if (((uint64_t) *pte) & PTE_P) {
			void *va = (void *) (((uint64_t) pml4_index << PML4SHIFT) |
								 ((uint64_t) pdp_index << PDPESHIFT) |
								 ((uint64_t) pdx_index << PDXSHIFT) |
								 ((uint64_t) i << PTXSHIFT));
			if (!func (pte, va, aux))
				return false;
		}
	}
	return true;
}

static bool
pgdir_for_each (uint64_t *pdp, pte_for_each_func *func, void *aux,
		unsigned pml4_index, unsigned pdp_index) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pte = ptov((uint64_t *) pdp[i]);
		if (((uint64_t) pte) & PTE_P)
			if (!pt_for_each ((uint64_t *) PTE_ADDR (pte), func, aux,
					pml4_index, pdp_index, i))
				return false;
	}
	return true;
}

static bool
pdp_for_each (uint64_t *pdp,
		pte_for_each_func *func, void *aux, unsigned pml4_index) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pde = ptov((uint64_t *) pdp[i]);
		if (((uint64_t) pde) & PTE_P)
			if (!pgdir_for_each ((uint64_t *) PTE_ADDR (pde), func,
					 aux, pml4_index, i))
				return false;
	}
	return true;
}

/* Apply FUNC to each available pte entries including kernel's. */
bool
pml4_for_each (uint64_t *pml4, pte_for_each_func *func, void *aux) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pdpe = ptov((uint64_t *) pml4[i]);
		if (((uint64_t) pdpe) & PTE_P)
			if (!pdp_for_each ((uint64_t *) PTE_ADDR (pdpe), func, aux, i))
				return false;
	}
	return true;
}

/**
 * pt_destroy, pgdir_destroy, pdpe_destroy: 페이지 테이블의 할당을 해제하고 해당 메모리를 해제하는데 사용된다.
*/
static void
pt_destroy (uint64_t *pt) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pte = ptov((uint64_t *) pt[i]);
		if (((uint64_t) pte) & PTE_P)
			palloc_free_page ((void *) PTE_ADDR (pte));
	}
	palloc_free_page ((void *) pt);
}

static void
pgdir_destroy (uint64_t *pdp) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pte = ptov((uint64_t *) pdp[i]);
		if (((uint64_t) pte) & PTE_P)
			pt_destroy (PTE_ADDR (pte));
	}
	palloc_free_page ((void *) pdp);
}

static void
pdpe_destroy (uint64_t *pdpe) {
	for (unsigned i = 0; i < PGSIZE / sizeof(uint64_t *); i++) {
		uint64_t *pde = ptov((uint64_t *) pdpe[i]);
		if (((uint64_t) pde) & PTE_P)
			pgdir_destroy ((void *) PTE_ADDR (pde));
	}
	palloc_free_page ((void *) pdpe);
}

/* Destroys pml4e, freeing all the pages it references. */
void
pml4_destroy (uint64_t *pml4) {
	if (pml4 == NULL)
		return;
	ASSERT (pml4 != base_pml4);

	/* if PML4 (vaddr) >= 1, it's kernel space by define. */
	uint64_t *pdpe = ptov ((uint64_t *) pml4[0]);
	if (((uint64_t) pdpe) & PTE_P)
		pdpe_destroy ((void *) PTE_ADDR (pdpe));
	palloc_free_page ((void *) pml4);
}

/* Loads page directory PD into the CPU's page directory base
 * register. */
void
pml4_activate (uint64_t *pml4) {
	lcr3 (vtop (pml4 ? pml4 : base_pml4));
}

/* Looks up the physical address that corresponds to user virtual
 * address UADDR in pml4.  Returns the kernel virtual address
 * corresponding to that physical address, or a null pointer if
 * UADDR is unmapped. */
void *
pml4_get_page (uint64_t *pml4, const void *uaddr) {
	ASSERT (is_user_vaddr (uaddr));

	uint64_t *pte = pml4e_walk (pml4, (uint64_t) uaddr, 0);

	if (pte && (*pte & PTE_P))
		return ptov (PTE_ADDR (*pte)) + pg_ofs (uaddr);
	return NULL;
}

/* Adds a mapping in page map level 4 PML4 from user virtual page
 * UPAGE to the physical frame identified by kernel virtual address KPAGE.
 * UPAGE must not already be mapped. KPAGE should probably be a page obtained
 * from the user pool with palloc_get_page().
 * If WRITABLE is true, the new page is read/write;
 * otherwise it is read-only.
 * Returns true if successful, false if memory allocation
 * failed. */
/**
 * pml4_set_page: 페이지 맵 레벨4(PML4)에 대한 매핑을 추가한다.
 * 사용자 가상 페이지(UPAGE)와 커널 가상 주소(KPAGE)에 해당하는 물리적 프레임 간의 매핑을 설정한다.
 * pml4: 테이블의 시작 주소, upage: 사용자 가상 페이지 주소->이미 매핑이 존재하지 않아야 한다.
 * kpage: 커널 가상 주소에 해당하는 물리적 프레임의 주소 -> palloc_get_page()를 사용하여 사용자 풀에서 얻은 페이지
 * rw: 새로운 페이지의 속성을 지정하는 플래그(true: 읽기/쓰기, false: 읽기 전용)
*/
bool
pml4_set_page (uint64_t *pml4, void *upage, void *kpage, bool rw) {
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (pg_ofs (kpage) == 0);
	ASSERT (is_user_vaddr (upage));
	ASSERT (pml4 != base_pml4);

	// pml4e_walk: PML4 엔트리에 대한 포인터를 얻는다. 
	// upag에 해당하는 페이지 테이블 엔트리가 이미 존재한다면 이를 반환한다.
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) upage, 1);

	if (pte)
		*pte = vtop (kpage) | PTE_P | (rw ? PTE_W : 0) | PTE_U;	
		// 물리 주소를 가상 주소로 변환하여 엔트리에 저장하고, 페이지 플래그를 설정한다.
	return pte != NULL;
}

/* Marks user virtual page UPAGE "not present" in page
 * directory PD.  Later accesses to the page will fault.  Other
 * bits in the page table entry are preserved.
 * UPAGE need not be mapped. */
void
pml4_clear_page (uint64_t *pml4, void *upage) {
	uint64_t *pte;
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (is_user_vaddr (upage));

	pte = pml4e_walk (pml4, (uint64_t) upage, false);

	if (pte != NULL && (*pte & PTE_P) != 0) {
		*pte &= ~PTE_P;
		if (rcr3 () == vtop (pml4))
			invlpg ((uint64_t) upage);
	}
}

/* Returns true if the PTE for virtual page VPAGE in PML4 is dirty,
 * that is, if the page has been modified since the PTE was
 * installed.
 * Returns false if PML4 contains no PTE for VPAGE. */
bool
pml4_is_dirty (uint64_t *pml4, const void *vpage) {
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) vpage, false);
	return pte != NULL && (*pte & PTE_D) != 0;
}

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
 * in PML4. */
void
pml4_set_dirty (uint64_t *pml4, const void *vpage, bool dirty) {
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) vpage, false);
	if (pte) {
		if (dirty)
			*pte |= PTE_D;
		else
			*pte &= ~(uint32_t) PTE_D;

		if (rcr3 () == vtop (pml4))
			invlpg ((uint64_t) vpage);
	}
}

/* Returns true if the PTE for virtual page VPAGE in PML4 has been
 * accessed recently, that is, between the time the PTE was
 * installed and the last time it was cleared.  Returns false if
 * PML4 contains no PTE for VPAGE. */
bool
pml4_is_accessed (uint64_t *pml4, const void *vpage) {
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) vpage, false);
	return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void
pml4_set_accessed (uint64_t *pml4, const void *vpage, bool accessed) {
	uint64_t *pte = pml4e_walk (pml4, (uint64_t) vpage, false);
	if (pte) {
		if (accessed)
			*pte |= PTE_A;
		else
			*pte &= ~(uint32_t) PTE_A;

		if (rcr3 () == vtop (pml4))
			invlpg ((uint64_t) vpage);
	}
}
