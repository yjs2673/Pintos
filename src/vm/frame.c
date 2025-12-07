#include "frame.h"
#include "page.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

struct list_elem *frame_clock;
struct list frame_list;
struct lock frame_lock;

void frame_init (void){
  frame_clock = NULL;
  list_init (&frame_list);
  lock_init (&frame_lock);
}

struct list_elem* vm_frame_next () {
  if (list_empty (&frame_list)) return frame_clock;

  struct list_elem *next_elem;
  bool reset_clock = (frame_clock == NULL || frame_clock == list_end (&frame_list));

  if (reset_clock) next_elem = list_begin (&frame_list);
  else next_elem = list_next (frame_clock); // 유효하다면 다음 칸으로 이동

  if (next_elem == list_end (&frame_list)) return list_begin (&frame_list);

  return next_elem;
}

static struct frame* vm_find_frame (void *kaddr) {
  struct list_elem *e = list_begin (&frame_list);

  while (true) {
    if (e == list_end (&frame_list)) break;

    struct frame *current_frame = list_entry (e, struct frame, frame_elem);
    
    if (current_frame->kaddr == kaddr) return current_frame; // 주소 비교

    e = list_next (e);
  }
    
  return NULL;
}

static void vm_insert_frame (struct frame *frame) {
  struct list *target_list = &frame_list;
  struct lock *target_lock = &frame_lock;

  lock_acquire (target_lock);
  list_push_back (target_list, &(frame->frame_elem));
  lock_release (target_lock);
}

static void vm_delete_frame (struct frame *frm) {
  bool is_clock_target = (frame_clock == &frm->frame_elem);
  frame_clock = is_clock_target ? list_next (frame_clock) : frame_clock;
  list_remove (&frm->frame_elem);
}

static void vm_second_chance (void) {
  // 초기화
  frame_clock = vm_frame_next ();
  lock_acquire (&frame_lock);

  if (!frame_clock) {
    lock_release (&frame_lock);
    return;
  }

  struct frame *victim = list_entry (frame_clock, struct frame, frame_elem);

  // Victim 선정
  while (true) {
    bool has_pte = (victim->pte != NULL);
    bool is_accessed = has_pte && pagedir_is_accessed (victim->thread->pagedir, victim->pte->vaddr);

    if (!is_accessed) break; // Accessed 비트가 0이면 루프 탈출 (Victim 선정)

    // Accessed 비트 청소 (1 -> 0)
    pagedir_set_accessed (victim->thread->pagedir, victim->pte->vaddr, 0);

    // 다음 후보 탐색
    frame_clock = vm_frame_next ();
    if (!frame_clock) {
       lock_release (&frame_lock);
       return;
    }
    victim = list_entry (frame_clock, struct frame, frame_elem);
  }

  // 스왑 아웃 여부 결정
  bool need_swap = false;
  if (victim->pte != NULL) {
      bool is_binary_dirty = (victim->pte->type == BINARY) && 
                              pagedir_is_dirty (victim->thread->pagedir, victim->pte->vaddr);
      bool is_swapped_type = (victim->pte->type == SWAPPED);
      
      need_swap = is_binary_dirty || is_swapped_type;
  }

  // 스왑 및 정리 수행
  if (need_swap) {
      victim->pte->swap_slot = swap_out (victim->kaddr);
      if (victim->pte->type == BINARY) victim->pte->type = SWAPPED;
  }

  if (victim->pte) {
      victim->pte->is_loaded = false;
      pagedir_clear_page (victim->thread->pagedir, victim->pte->vaddr);
  }
  
  vm_delete_frame (victim);
  palloc_free_page (victim->kaddr);
  free (victim);
  lock_release (&frame_lock);
}

bool load_file_to_page (void *kaddr, struct pt_entry *pte)  {
  lock_acquire (&filesys_lock);
    
  size_t bytes_read = file_read_at(pte->file, kaddr, pte->read_bytes, pte->offset);
    
  lock_release (&filesys_lock);

  if (bytes_read != pte->read_bytes) return false;
    
  if(pte->zero_bytes > 0) memset (kaddr + pte->read_bytes, 0, pte->zero_bytes);
  
  return true; 
}

struct frame* vm_alloc_page (enum palloc_flags flags) {
  if ((flags & PAL_USER) == 0) flags |= PAL_USER;

  uint8_t *p_page = NULL;

retry_allocation:
  p_page = palloc_get_page(flags);
  
  if (p_page == NULL) {
    vm_second_chance ();
    goto retry_allocation;
  }

  struct frame *frm = malloc (sizeof(struct frame));
  
  if (frm == NULL) goto cleanup_and_fail;

  // 정상 초기화
  frm->thread = thread_current ();
  frm->kaddr = p_page;
  frm->pte = NULL;

  vm_insert_frame (frm);
  return frm;

// 에러 처리 및 자원 해제
cleanup_and_fail:
  palloc_free_page (p_page);
  return NULL;
}

void vm_free_page (void *kaddr) {
  struct frame *frm = vm_find_frame (kaddr);

  if (frm != NULL) {
    struct pt_entry *entry = frm->pte;

    if (entry != NULL) {
        pagedir_clear_page (frm->thread->pagedir, entry->vaddr);
    }
    
    vm_delete_frame (frm);
    palloc_free_page (frm->kaddr);
    free (frm);
  } 
  else return;
}