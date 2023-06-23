/* vm.c: Generic interface for virtual memory objects. */
#include "string.h"
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "list.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
    vm_anon_init ();
    vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
    pagecache_init ();
#endif
    register_inspect_intr ();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
    int ty = VM_TYPE (page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE (page->uninit.type);
        default:
            return ty;
    }
}

// 연결 리스트를 사용하여 프레임 테이블을 구현한다. 
struct list frame_table;

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
// upage: 생성될 uninit 페이지의 가상 주소를 가리키는 포인터
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
        vm_initializer *init, void *aux) {

    // ✅ TEST : vm_alloc_page_with_initializer
    // bool unit_test_vm_alloc_page_with_initializer = false;
    ASSERT (VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current ()->spt;

    /* Check wheter the upage is already occupied or not. */
    // 0. spt_find_page로 `upage`가 이미 할당되었는지 확인한다.
    if (spt_find_page (spt, upage) == NULL) {       // upage(가상 주소)에 데이터가 없다면
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        // 1. 새로운 페이지를 생성한다. : 가상 메모리와 관련된 정보를 갖는다.
        struct page *p = (struct page *)malloc(sizeof(struct page));
        /**
         * page_initializer가 3개의 매개변수를 갖는 함수를 가리키는 함수 포인터이다. 
        */
    	bool (*page_initializer) (struct page *, enum vm_type, void *); 

        // 2. VM 타입에 따른 초기화 함수를 호출한다.
        switch (VM_TYPE(type))
        {
        case VM_ANON:
            page_initializer = anon_initializer;
            break;
        case VM_FILE:
            page_initializer = file_backed_initializer;
            break;
        }

        // 3. uninit_new를 호출하여 페이지 구조체를 생성한다. -> uninit 상태의 페이지 구조체는 초기화되지 않은 상태를 나타낸다.
        uninit_new(p, upage, init, type, aux, page_initializer);
        
        /* TODO: Insert the page into the spt. */
        return spt_insert_page(spt, p);
    }
    // ✅ TEST : vm_alloc_page_with_initializer
    // unit_test_vm_alloc_page_with_initializer = true;
    // ASSERT(unit_test_vm_alloc_page_with_initializer != true);
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* TODO: Fill this function. */
    // ✅ TEST: spt_find_page
	// bool unit_test_spt_find_page = false; 
    
    // page dummy 데이터를 할당시킨다.
	struct page *page = (struct page *)malloc(sizeof(struct page));
    // pg_round_down: Round down to neareset page boundary
	page->va = pg_round_down(va);   // https://github.com/Blue-club/pintos2_Team3/discussions/8#discussion-5312566

	// spt_hash에서 va 객체를 찾는다.
	struct hash_elem *e = hash_find(&spt->spt_hash, &page->hash_elem);
	free(page);

	// ✅ TEST: spt_find_page
	// unit_test_spt_find_page = true;
	// ASSERT(unit_test_spt_find_page != true);	// unit_test_spt_find_page가 true이면 멈춘다.

	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
        struct page *page UNUSED) {
    int succ = false;
    /* TODO: Fill this function. */
    // hash_insert: 이미 page가 들어가있는 상태라면 old값을 return한다.
    struct hash_elem *result = hash_insert(&spt->spt_hash, &page->hash_elem);

    if (result == NULL){
        succ = true;
    }
    return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
    vm_dealloc_page (page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
    struct frame *victim = NULL;
     /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
    struct frame *victim UNUSED = vm_get_victim ();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    /* TODO: Fill this function. */
    // ✅ TEST: vm_get_frame 
    // bool unit_vm_get_frame = false;

    // 할당된 메모리의 주소를 반환하여 frame의 kva에 대입한다.
    frame->kva = palloc_get_page(PAL_USER);
    frame->page = NULL;

    // 페이지 할당을 실패한 경우
    if (frame->kva == NULL) {
        PANIC ("todo");
        // vm_evict_frame(); // 정상적으로 물리 프레임 주소를 할당받지 못할 경우
    }
    
    // frame_table에 넣어서 관리한다.
    list_push_back(&frame_table, &frame->frame_elem);
    
    ASSERT (frame != NULL);
    ASSERT (frame->page == NULL);

    // ✅ TEST: vm_get_frame 
    // unit_vm_get_frame = true;
    // ASSERT(unit_vm_get_frame != true);

    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/**
 * 함수 페이지 폴트 처리
 * f: intr_frame 포인터, addr: 오류 주소, user: 사용자 공간에서 오류가 발생했는지 나타내는 플래그
 * write: 쓰기 액세스로 인한 것, not_present: 폴트가 존재하지 않는 페이지로 인한 것인가
*/
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
        bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */
    if (addr == NULL)
    {
        return false;
    }
    
    // kernel 영역인가(vaddr은 virtual address, 즉 가상 주소를 말한다)
    if (is_kernel_vaddr(addr))
    {
        return false;
    }

    // 존재하지 않은 페이지에 접근하여 page fault가 발생했다면 -> 접근한 메모리에 physical memory가 존재하지 않는다면
    if (not_present)
    {
        page = spt_find_page(spt, addr);
        if (page == NULL)
        {
            return false;
        }
        
        return vm_do_claim_page (page);
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
    destroy (page);
    free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
    /* TODO: Fill this function */
    // 물리 프레임과 연결할 프레임을 찾는다.
    struct page *page = spt_find_page (&thread_current()->spt, va);
    if (page == NULL) {
        return false;
    }

    return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
// 해당 페이지에 물리 프레임 할당을 요청한다.
static bool
vm_do_claim_page (struct page *page) {
    struct frame *frame = vm_get_frame ();  // 빈 프레임을 얻는다. -> frame 변수에 얻은 프레임의 주소가 할당된다.
    // page가 이미 다른 물리 주소 kva와 미리 연결되어있는지 확인한다.
    if (page->frame != NULL) {
        return false;
    }

    /* Set links */
    frame->page = page;     // 객체 간의 링크를 설정한다.
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    // page 객체의 va 멤버에 frame의 kva 멤버(프레임의 가상 주소)를 할당한다.
    // 페이지 테이블의 엔트리에 페이지의 가상 주소(VA)를 매핑하는 작업을 수행한다.
    // page->va= frame->kva;   // 잘못된 코드

    struct thread *current = thread_current();
    // 🚨 writable 수정 필요
    pml4_set_page(current->pml4, page->va, frame->kva, 1);

    // swap_in() 함수를 호출하여 페이지를 스왑 인(swap in)하고, 스왑된 페이지를 프레임의 가상 주소(KVA)로 복구한다. (by MMU)
    // swap_in : 해당 페이지를 물리 메모리에 올려준다.
    return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
    // supplemental_page_table 테이블을 초기화한다.
    
    // ✅ TEST: supplemental_page_table_init test
    // bool initialize_hash = hash_init(&spt->spt_hash, hashing, hash_less, NULL);
    // ASSERT(initialize_hash != true); // initialize_hash가 true라면 프로그램을 종료시킨다.

    hash_init(&spt->spt_hash, hashing, hash_less, NULL);
}

/* Copy supplemental page table from src to dst */
/**
 * src -> dst
*/
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
        struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first(&i, &src->spt_hash); // 가장 첫번째 원소
    while (hash_next(&i))
    {
        // hash_elem과 연결된 page를 찾아 해당 페이지 구조체 정보를 저장한다.
        struct page *src_page = hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        if (type == VM_UNINIT)
        {
            // UNINIT 페이지 생성 및 초기화
            vm_initializer *initializer = src_page->uninit.init;
            void *aux = src_page->uninit.aux;
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, initializer, aux);
            continue;
        } 

        // else {
        //     // 여기에 페이지 요청하는 부분 추가하니까 틀렸음    
        // }
        
        // 패이지 요청
        if (!vm_alloc_page(VM_ANON, upage, writable))
        {
            return false;   
        }
            
        // 페이지 할당
        if (!vm_claim_page(upage))
        {
            return false;
        }

        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->spt_hash, spt_clear_action);  // hash_destroy vs hash_clear: hash_destroy -> 아마도 hash_init 전으로 돌아가는 것 같음!!!
}

// hash_action_function
void
spt_clear_action(struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);    
}

/**
 * hashing 함수를 작성한다. -> hash byte 함수를 사용한다.
*/
uint64_t
hashing (const struct hash_elem *e, void *aux) {
    struct page *hash_page = hash_entry(e, struct page, hash_elem);
    uint64_t hash = hash_bytes(&hash_page->va, sizeof(hash_page->va));
    return hash;
}

/**
 * hash_elem a의 va(virtual address)와 hash_elem b의 va를 비교한다.
 * A < B - >true / A >= B -> false
 * hash_less 비교함수는 나중에 find_elem할 때 사용될 예정!
*/
bool
hash_less (struct hash_elem *a, struct hash_elem *b, void *aux) {
    struct page *page_a = hash_entry(a, struct page, hash_elem);
    struct page *page_b = hash_entry(b, struct page, hash_elem);

    return page_a->va < page_b->va;
}

void
frame_table_init () {
    list_init(&frame_table);
}