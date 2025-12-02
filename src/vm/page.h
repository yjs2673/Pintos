#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "filesys/file.h"
#include "threads/thread.h"

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

struct vm_entry {
    uint8_t type;               // VM_BIN, VM_FILE, VM_ANON
    void *vaddr;                // 가상 주소 (Page Aligned)
    bool writable;              // 쓰기 가능 여부
    
    bool is_loaded;             // 메모리에 로드 되었는지
    bool pinned;                // Frame Eviction 방지

    struct file *file;          // 파일 포인터 (Binary or Mmap)
    size_t offset;              // 파일 오프셋
    size_t read_bytes;          // 파일에서 읽을 바이트 수
    size_t zero_bytes;          // 0으로 채울 바이트 수

    size_t swap_slot;           // 스왑 슬롯 인덱스 (Swap out 된 경우)

    struct hash_elem elem;      // 해시 테이블 엘리먼트
};

void vm_init (struct hash *vm);
void vm_destroy (struct hash *vm);

struct vm_entry *find_vme (void *vaddr);
bool insert_vme (struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

bool load_file (void *kaddr, struct vm_entry *vme);

#endif