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
struct lock frame_lock;
struct list frame_list;

bool 
load_file_to_page(void *kaddr, struct pt_entry *pte) 
{
    lock_acquire(&filesys_lock);
    
    size_t bytes_read = file_read_at(pte->file, kaddr, pte->read_bytes, pte->offset);
    
    lock_release(&filesys_lock);

    if (bytes_read != pte->read_bytes) return false;
    
    if(pte->zero_bytes > 0){
        memset(kaddr + pte->read_bytes, 0, pte->zero_bytes);
    }
    return true; 
}

static struct frame *
ft_find_frame(void *kaddr) {
    struct frame *frm;
    struct list_elem *elem;

    for (elem = list_begin(&frame_list); elem != list_end(&frame_list); elem = list_next(elem)) {
        frm = list_entry(elem, struct frame, frame_elem);
         if (frm->kaddr == kaddr) {
            return frm; // 일치하는 frame을 찾으면 반환
        }
    }
    
    return NULL; // 찾지 못하면 NULL 반환
}

void
frame_init (void)
{
  frame_clock = NULL;
  list_init (&frame_list);
  lock_init (&frame_lock);
}

struct frame *alloc_page (enum palloc_flags flags)
{
  /* [FIX] PAL_USER 플래그가 포함되어야 함 */
    if (!(flags & PAL_USER)) flags |= PAL_USER;

    uint8_t *p_page = palloc_get_page(flags);
    
    while(p_page == NULL){
        ft_second_chance ();
        p_page = palloc_get_page(flags);
    }

    struct frame *frm = malloc(sizeof(struct frame));
    if (frm == NULL) {
        palloc_free_page(p_page);
        return NULL;
    }

    frm->thread = thread_current();
    frm->kaddr = p_page;
    frm->pte = NULL; /* 초기화 */

    ft_insert_frame (frm);
    return frm;
}

void 
free_page (void *kaddr)//완
{
  struct frame *frm = NULL;

    frm = ft_find_frame(kaddr);
    if(frm!=NULL){
        if(frm->pte != NULL) pagedir_clear_page (frm->thread->pagedir, frm->pte->vaddr);
        ft_delete_frame(frm);
        palloc_free_page(frm->kaddr);
        free(frm);
    }
}

static void
ft_insert_frame (struct frame *frame)
{
  lock_acquire(&frame_lock);
  list_push_back (&frame_list, &(frame->frame_elem));
  lock_release(&frame_lock);
}


static void
ft_delete_frame (struct frame *frm)
{
  // lock_acquire(&frame_lock);
  if(frame_clock == &frm->frame_elem)
        frame_clock = list_next(frame_clock);

    list_remove(&frm->frame_elem);
  // lock_release(&frame_lock);
}


struct list_elem *frame_next(){//완
    //원형순회를 위한 next 알고리즘
    struct list_elem *nxt;
    if(list_empty(&frame_list)) return frame_clock;
    if(frame_clock == NULL || frame_clock == list_end(&frame_list)){
        nxt = list_begin(&frame_list);
    }
    else nxt = list_next(frame_clock);

    if(nxt == list_end(&frame_list)) nxt = list_begin(&frame_list);

    return nxt;
}
static void
ft_second_chance (void)
{
  frame_clock = frame_next();
  lock_acquire (&frame_lock);
  if (!frame_clock)
    {
      lock_release (&frame_lock);
      return;
    }

  struct frame *victim = list_entry (frame_clock, struct frame, frame_elem);
    while(victim->pte != NULL && pagedir_is_accessed (victim->thread->pagedir, victim->pte->vaddr)){
      if(victim->pte!=NULL) pagedir_set_accessed (victim->thread->pagedir, victim->pte->vaddr, 0);
      frame_clock = frame_next();
        if(!frame_clock){
          lock_release (&frame_lock);
          return;
        }
      victim = list_entry (frame_clock, struct frame, frame_elem);
    }
    
    if(victim->pte!=NULL && victim->pte->type == BINARY){
       if (pagedir_is_dirty (victim->thread->pagedir, victim->pte->vaddr))
        {
          victim->pte->swap_slot = swap_out (victim->kaddr);
          victim->pte->type = SWAPPED;
        }
    }
  else if(victim->pte!=NULL && victim->pte->type == SWAPPED)
    {
      victim->pte->swap_slot = swap_out (victim->kaddr);
    }
  if(victim->pte) victim->pte->is_loaded = false;
  if(victim->pte) pagedir_clear_page (victim->thread->pagedir, victim->pte->vaddr);
  ft_delete_frame (victim);
  palloc_free_page (victim->kaddr);
  free (victim);
  lock_release (&frame_lock);
  return;
}