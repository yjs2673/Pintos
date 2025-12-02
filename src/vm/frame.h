#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "vm/page.h"
#include "threads/palloc.h"
#include <list.h>

struct frame {
    void *kaddr;                // 커널 가상 주소 (Physical Frame)
    struct vm_entry *vme;       // 매핑된 페이지 정보
    struct thread *thread;      // 소유 스레드
    struct list_elem elem;      // 리스트 연결용
};

void frame_init (void);
struct page *frame_alloc (enum palloc_flags flags, struct vm_entry *vme);
void frame_free (void *kaddr);
void __frame_free (void *kaddr); // 내부 호출용 (Lock 미사용)

#endif