#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/synch.h"
// 오류 를 일으켜서 추가한 라이브러리.
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "threads/palloc.h"
#include "include/lib/user/syscall.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void check_address(void *addr);
bool check_fd(int fd);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int exec(const char *cmd_line);
int wait(int pid);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
tid_t fork(const char *thread_name, struct intr_frame *f);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	int systemcall_num = f->R.rax;
	// printf("%d\n", systemcall_num);

	switch (systemcall_num)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_WAIT:
		f->R.rax = wait(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	case SYS_SEEK:
		seek(f->R.rdi, f->R.rsi);
		break;
	case SYS_TELL:
		f->R.rax = tell(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_MMAP:
		f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
		break;
	case SYS_MUNMAP:
		munmap(f->R.rdi);
		break;
	}
}

void check_address(void *addr){
	if (addr == NULL)
		exit(-1);
	if (!is_user_vaddr(addr))
		exit(-1);
	/**
	 * syscall에서는 eager loading이었기 때문에 로딩이 된 상태이지만, lazy loading은 아직 물리 메모리에 로딩되지 않아서 확인할 
	 * 지금은 page fault가 구현되어있으니까, 할 필요 없다.
	*/
	// if (pml4_get_page(thread_current()->pml4, addr) == NULL)	// 🚨 check address 확인 필요
	// 	exit(-1);
	// if (addr == NULL || !(is_user_vaddr(addr))||pml4_get_page(cur->pml4, addr) == NULL){
	// 	exit(-1);
	// }
}

bool check_fd(int fd){
	if(fd < 0 || fd >= FDT_COUNT_LIMIT){
		return false;
	}
	else {
		return true;
	}
}

// pintos를 종료시키는 시스템 콜
void halt(void){
	power_off(); // 핀토스를 종료시키는 함수
}

// 현재 프로세스를 종료시키는 시스템 콜
void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n",thread_name(), status);
	thread_exit();
}

//파일을 생성하는 시스템 콜
bool create(const char *file, unsigned initial_size){
	check_address(file);
	return filesys_create(file,initial_size); // 파일 이름과 파일 사이즈를 인자 값으로 받아 파일을 생성하는 함수
}

//파일을 삭제하는 시스템 콜
bool remove(const char *file){
	check_address(file);
	return filesys_remove(file); // 파일 이름에 해당하는 파일을 제거하는 함수
}

int exec(const char *cmd_line)
{
	check_address(cmd_line);	

	// 새 스레드를 생성하지 않고 process_exec을 호출한다.

	char *cmd_line_copy;	// filename으로 const char* 복사본을 만든다. 
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL) // 메모리 할당 실패시 exit(-1)
		exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE); // cmd_line을 복사한다.

	if (process_exec(cmd_line_copy) == -1)
		exit(-1); // 실패 시 status -1로 종료한다.
}

int wait(int pid)
{
	return process_wait(pid);
}

// 파일을 열 때 사용하는 시스템 콜
int open(const char *file_name)
{
	check_address(file_name);
	struct file *file = filesys_open(file_name);
	if (file == NULL)
		return -1;
	int fd = process_add_file(file);
	if (fd == -1) // 여기에 땀 있었음.(닦아줌)
		file_close(file);
	return fd;
}

// 파일의 크기를 알려주는 시스템 콜
int filesize(int fd)
{
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return -1;
	return file_length(file);
}

// 열린 파일의 데이터를 읽는 시스템 콜
int read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);

	char *ptr = (char *)buffer;
	int bytes_read = 0;

	lock_acquire(&filesys_lock); // 락을 요구합니다.
	if(fd == STDIN_FILENO)
	{
		for (int i = 0; i < size; i++)
		{
			*ptr++ = input_getc();
			bytes_read++;
		}
		lock_release(&filesys_lock);
	}
	else
	{
		if (fd < 2)
		{
			lock_release(&filesys_lock);
			return -1;
		}
		struct file *file = process_get_file(fd);
		struct thread *thread = thread_current();
		struct page *page = spt_find_page(&thread->spt, buffer);

		if(page == NULL || page->writable == 0) {	// buffer(내가 본 책의 내용을 작성하는 공책의 권한을 확인해야 한다.)
			lock_release(&filesys_lock);
			exit(-1);
		}

		if (file == NULL)
		{
			lock_release(&filesys_lock);
			return -1;
		}
		bytes_read = file_read(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_read;
}

// 열린 파일의 데이터를 기록 시스템 콜
int write(int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	int bytes_write = 0;
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		bytes_write = size;
	}
	else
	{
		if (fd < 2)
			return -1;
		struct file *file = process_get_file(fd);
		if (file == NULL)
			return -1;
		lock_acquire(&filesys_lock);
		bytes_write = file_write(file, buffer, size);
		lock_release(&filesys_lock);
	}
	return bytes_write;
}


// 열린 파일의 위치를 이동하는 시스템 콜
void seek(int fd, unsigned position)
{
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return;
	file_seek(file, position);
}

// 열린 파일의 위치를 알려주는 시스템 콜
unsigned tell(int fd)
{
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return;
	return file_tell(file);
}

// 열린 파일을 닫는 시스템 콜
void close(int fd)
{
	struct file *file = process_get_file(fd);
	if (file == NULL)
		return;
	file_close(file);
	process_close_file(fd);
}


tid_t fork(const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}


void *mmap(void *addr, size_t length, int writable, int fd, off_t offset)
{
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct file *file = process_get_file(fd);

	if (file == NULL)
	{
		return MAP_FAILED;
	}

	// offset 값이 PGSIZE에 알맞게 align되어 있는지 확인한다.
	if (pg_round_down(offset) != offset)
	{ 
		return MAP_FAILED;
	}

	// addr의 값이 유효한지 확인한다.
	// addr이 NULL 값인가?
	if (addr == NULL || addr == 1) 
	{
		return MAP_FAILED;
	}

	if (!is_user_vaddr(addr + length) || !is_user_vaddr(addr))
	{	
		return MAP_FAILED;
	}
	
	// 시작점이 PGSIZE로 정렬되어있는지 확인한다.
	if (pg_round_down(addr) != addr)
	{
		return MAP_FAILED;
	}

	// length가 0이하인지 확인한다.
	if ((long long)length <= 0)		// int 형으로 왜 바꿔주어야 하는지
	{
		// printf("long long: %lu\n", length);
		return MAP_FAILED;
	}

	// 매핑하려는 페이지가 이미 존재하는 페이지와 겹치면(==spt에 존재하는 페이지)
	if (spt_find_page(spt, addr) != NULL) 
	{
		return MAP_FAILED;
	}

	// fd값이 표준입력 또는 표준 출력인지 확인하고 해당 fd를 통해 가져온 file 구조체가 유효한지 검증한다. 
	if (!check_fd(fd)) {
		return MAP_FAILED;
	}

	if (check_fd(fd))
	{
		// 파일 구조체 검증
		if (file_length(file) == NULL)
		{
			return MAP_FAILED;
		}
	}

	// 검증을 성공적으로 통과하면 do_mmap() 함수 호출하여 실제 메모리 매핑을 진행한다.
	return do_mmap(addr, length, writable, file, offset);
}

void munmap (void *addr)
{
	do_munmap(addr);	
}