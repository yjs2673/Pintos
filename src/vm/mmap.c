#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include <string.h>
#include <list.h>

/* Map a file into memory */
int mmap (int fd, void *addr) {
  struct thread *cur = thread_current ();
  
  /* 1. 기본 유효성 검사 */
  if (addr == NULL || pg_ofs (addr) != 0)
    return -1;
  
  if (fd == 0 || fd == 1) /* stdin/stdout 매핑 불가 */
    return -1;
  
  /* fd 확인 (thread.h에 정의된 fd 배열 사용) */
  if (fd < 2 || fd >= 128 || cur->fd[fd] == NULL)
    return -1;

  struct file *f = cur->fd[fd];
  
  lock_acquire(&filesys_lock);
  off_t file_size = file_length (f);
  lock_release(&filesys_lock);

  if (file_size == 0)
    return -1;
  
  /* 2. 주소 공간 겹침 확인 (Check if address range is valid and unmapped) */
  /* pt_entry 구조체를 사용하며 pt_find_entry로 검색 */
  for (off_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      if (pt_find_entry (addr + ofs) != NULL)
        return -1;
      
      // 스택 영역 침범 확인 등 추가적인 검사가 필요하다면 여기서 수행
      if (!is_user_vaddr (addr + ofs))
        return -1;
    }
  
  /* 3. 파일 재오픈 (독립적인 오프셋 관리를 위해) */
  lock_acquire(&filesys_lock);
  struct file *reopened = file_reopen (f);
  lock_release(&filesys_lock);

  if (reopened == NULL)
    return -1;
  
  /* 4. mmap_file 구조체 생성 및 초기화 */
  struct mmap_file *mf = malloc (sizeof (struct mmap_file));
  if (mf == NULL)
    {
      lock_acquire(&filesys_lock);
      file_close (reopened);
      lock_release(&filesys_lock);
      return -1;
    }
  
  mf->mapid = cur->next_mapid++;
  mf->file = reopened;
  mf->vaddr = addr;
  mf->size = file_size;
  
  /* 5. 페이지 테이블 엔트리(pt_entry) 생성 및 등록 */
  size_t read_bytes = file_size;
  size_t offset = 0;
  void *upage = addr;

  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      struct pt_entry *pte = malloc (sizeof (struct pt_entry));
      if (pte == NULL)
        {
          // 실패 시 자원 정리 (이미 할당된 pte들과 mf 등을 정리해야 함)
          // 여기서는 편의상 -1 리턴으로 처리 (실제 구현 시 munmap 로직 활용 가능)
          free(mf);
          lock_acquire(&filesys_lock);
          file_close(reopened);
          lock_release(&filesys_lock);
          return -1;
        }
      
      /* page.h 의 pt_entry 구조체에 맞게 값 설정 */
      pte->file = reopened;
      pte->offset = offset;
      pte->read_bytes = page_read_bytes;
      pte->zero_bytes = page_zero_bytes;
      
      pte->vaddr = upage;
      pte->is_loaded = false;
      pte->writable = true;
      
      /* frame.c의 load_file_to_page가 BINARY 타입을 처리하므로 BINARY 사용 */
      pte->type = BINARY; 
      pte->swap_slot = 0;
      
      /* 해시 테이블에 삽입 (thread->pt 사용) */
      if (!pt_insert_entry (&cur->pt, pte))
        {
          free (pte);
          free (mf);
          lock_acquire(&filesys_lock);
          file_close (reopened);
          lock_release(&filesys_lock);
          return -1;
        }
      
      read_bytes -= page_read_bytes;
      offset += page_read_bytes;
      upage += PGSIZE;
    }
  
  list_push_back (&cur->mmap_list, &mf->elem);
  return mf->mapid;
}

/* Unmap a file from memory */
void munmap (int mapid) {
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct mmap_file *mf = NULL;
  
  /* 1. mmap_list에서 해당 mapid 찾기 */
  for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list); e = list_next (e))
    {
      struct mmap_file *temp = list_entry (e, struct mmap_file, elem);
      if (temp->mapid == mapid)
        {
          mf = temp;
          break;
        }
    }
  
  if (mf == NULL)
    return;
  
  /* 2. 해당 파일에 매핑된 모든 페이지 순회 및 해제 */
  /* pt_entry에 리스트 연결자가 없으므로 주소 범위를 계산하여 순회 */
  void *addr = mf->vaddr;
  size_t remaining_size = mf->size;

  while (remaining_size > 0)
    {
      struct pt_entry *pte = pt_find_entry(addr);

      if (pte != NULL)
        {
          /* 로드되어 있고 dirty 상태라면 파일에 기록 */
          if (pte->is_loaded)
            {
              if (pagedir_is_dirty (cur->pagedir, pte->vaddr))
                {
                  bool need_lock = !lock_held_by_current_thread (&filesys_lock);
                  if (need_lock) lock_acquire (&filesys_lock);
                  file_write_at (mf->file, pte->vaddr, pte->read_bytes, pte->offset);
                  if (need_lock) lock_release (&filesys_lock);
                }
            }
          
          /* 페이지 테이블에서 제거 및 프레임 해제 */
          /* pt_delete_entry 내부에서 vm_free_page와 free(pte)가 호출됨 */
          pt_delete_entry (&cur->pt, pte);
        }

      /* 다음 페이지로 이동 */
      if (remaining_size >= PGSIZE)
        {
          addr += PGSIZE;
          remaining_size -= PGSIZE;
        }
      else
        {
          remaining_size = 0;
        }
    }
  
  /* 3. mmap 구조체 및 파일 정리 */
  list_remove (&mf->elem);
  lock_acquire (&filesys_lock);
  file_close (mf->file);
  lock_release (&filesys_lock);
  free (mf);
}