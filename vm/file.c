/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
/**
 * addr: 가상 주소 공간, length: file의 길이, writable: 쓸 수 있는지 여부
 * file: 매핑할 파일, offset:  
 * load_segment를 생각해라!!!
*/
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// 인자로 들어온 file을 reopen()을 통해 동일한 파일에 대해 다른 주소를 가지는 파일 구조체를 생성한다.
	// reopen() -> mmap을 하는 동안 만약 외부에서 해당 파일을 close()하는 상황을 예외 처리하기 위해

	struct file *reopend_file = file_reopen(file);
	void *m_addr = addr;	// 매핑 성공 시, 파일이 매핑된 가상 주소

	// 매핑에 사용되는 총 페이지 수
	int total_page_count = 0;

	// length가 한 페이지 길이를 초과한 경우
	if (length <= PGSIZE)
	{
		total_page_count = 1;
	} else {
		// 나머지가 0이 아니다 -> 균등하게 나눌 수 없다.
		if (length % PGSIZE != 0)
		{
			total_page_count = length / PGSIZE + 1;
		} else {
			total_page_count = length / PGSIZE;
		}
	}
	
	size_t file_read_bytes = file_length(file) < length ? file_length(file) : length;
	size_t file_zero_bytes = PGSIZE - file_read_bytes % PGSIZE;

	ASSERT ((file_read_bytes + file_zero_bytes) % PGSIZE == 0);	// read_bytes와 zero_bytes 합이 페이지 크기 배수인가
	ASSERT (pg_ofs (addr) == 0);	// upage가 정렬되어 있는가
	ASSERT (offset % PGSIZE == 0);		// ofs가 페이지 정렬되어 있는가

	// read_byte와 zero_byte가 모두 처리될 때까지 반복한다.
	while (file_read_bytes > 0 || file_zero_bytes > 0) {
		size_t page_read_bytes = file_read_bytes < PGSIZE ? file_read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct lazy_load_segment_info *lazy_load_segment_info = malloc(sizeof(struct lazy_load_segment_info));

		if (lazy_load_segment_info == NULL){
			return false;
		}

		lazy_load_segment_info->file = file;
		lazy_load_segment_info->ofs = offset;
		lazy_load_segment_info->page_read_bytes = page_read_bytes;
		lazy_load_segment_info->page_zero_bytes = page_zero_bytes;

		if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_segment, lazy_load_segment_info)) {
			free(lazy_load_segment_info);
			return false;
		}

		file_read_bytes -= page_read_bytes;
		file_zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;			
	}

	return m_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
