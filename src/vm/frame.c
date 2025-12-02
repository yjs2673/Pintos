#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"

static struct list frame_table;
static struct lock frame_lock;

void frame_init (void) {
    list_init (&frame_table);
    lock_init (&frame_lock);
}

struct page *frame_alloc (enum palloc_flags flags, struct vm_entry *vme) {
    if ((flags & PAL_USER) == 0) return NULL;

    void *kaddr = palloc_get_page (flags);
    
    if (kaddr == NULL) {
        // [Eviction] 메모리가 부족하면 페이지 교체 수행
        struct list_elem *e = list_begin(&frame_table);
        
        lock_acquire(&frame_lock);
        while (true) {
            struct frame *f = list_entry(e, struct frame, elem);
            
            // Pinned 페이지는 건너뜀
            if (!f->vme->pinned) {
                 if (pagedir_is_accessed(f->thread->pagedir, f->vme->vaddr)) {
                     pagedir_set_accessed(f->thread->pagedir, f->vme->vaddr, false);
                 } else {
                     // Victim 선정
                     if (pagedir_is_dirty(f->thread->pagedir, f->vme->vaddr) || f->vme->type == VM_ANON) {
                         f->vme->type = VM_ANON;
                         f->vme->swap_slot = swap_out(f->kaddr);
                     }
                     f->vme->is_loaded = false;
                     pagedir_clear_page(f->thread->pagedir, f->vme->vaddr);
                     
                     __frame_free(f->kaddr); // 프레임 해제
                     free(f);
                     break;
                 }
            }
            e = list_next(e);
            if (e == list_end(&frame_table)) e = list_begin(&frame_table);
        }
        lock_release(&frame_lock);
        
        kaddr = palloc_get_page (flags); // 다시 할당 시도
        if (kaddr == NULL) PANIC ("Out of memory after eviction");
    }

    // 프레임 테이블 등록
    struct frame *f = malloc(sizeof(struct frame));
    f->kaddr = kaddr;
    f->vme = vme;
    f->thread = thread_current();
    
    lock_acquire (&frame_lock);
    list_push_back (&frame_table, &f->elem);
    lock_release (&frame_lock);

    return kaddr;
}

void frame_free (void *kaddr) {
    lock_acquire (&frame_lock);
    __frame_free(kaddr);
    lock_release (&frame_lock);
}

// Lock 없이 호출되는 내부 함수
void __frame_free (void *kaddr) {
    struct list_elem *e;
    for (e = list_begin (&frame_table); e != list_end (&frame_table); e = list_next (e)) {
        struct frame *f = list_entry (e, struct frame, elem);
        if (f->kaddr == kaddr) {
            list_remove (e);
            free (f);
            palloc_free_page (kaddr);
            return;
        }
    }
}