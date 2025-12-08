#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <hash.h>
#include "filesys/off_t.h"

/* mmap 정보를 관리하기 위한 구조체 정의 */
struct mmap_file {
    int mapid;                  /* 매핑 ID */
    struct file *file;          /* 매핑된 파일 객체 */
    struct list_elem elem;      /* thread->mmap_list 연결용 */
    void *vaddr;                /* 매핑 시작 가상 주소 */
    size_t size;                /* 매핑된 파일 크기 */
};

int mmap (int fd, void *addr);
void munmap (int mapid);

#endif
