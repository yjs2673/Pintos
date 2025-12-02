#include "vm/page.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <string.h>

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED);

void vm_init (struct hash *vm) {
    hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);
    return hash_bytes (&vme->vaddr, sizeof vme->vaddr);
}

static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem);
    struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem);
    return vme_a->vaddr < vme_b->vaddr;
}

struct vm_entry *find_vme (void *vaddr) {
    struct thread *t = thread_current();
    struct vm_entry vme;
    vme.vaddr = pg_round_down(vaddr);

    struct hash_elem *e = hash_find (&t->vm, &vme.elem);
    return e != NULL ? hash_entry (e, struct vm_entry, elem) : NULL;
}

bool insert_vme (struct hash *vm, struct vm_entry *vme) {
    return hash_insert (vm, &vme->elem) == NULL;
}

bool delete_vme (struct hash *vm, struct vm_entry *vme) {
    if (hash_delete (vm, &vme->elem) == NULL) return false;
    free (vme);
    return true;
}

void vm_destroy (struct hash *vm) {
    hash_destroy (vm, vm_destroy_func);
}

static void vm_destroy_func (struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vme = hash_entry (e, struct vm_entry, elem);
    
    // 로드된 상태라면 프레임 할당 해제 및 swap slot 해제 처리 필요
    // 현재 구현에서는 frame table에서 process exit시 처리한다고 가정하거나
    // 여기서 palloc_free_page를 호출하지 않고 frame table의 포인터만 끊어주는 것이 안전함.
    
    free (vme);
}

bool load_file (void *kaddr, struct vm_entry *vme) {
    if (vme->read_bytes > 0) {
        if ((int)vme->read_bytes != file_read_at (vme->file, kaddr, vme->read_bytes, vme->offset)) {
            return false;
        }
        memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
    } else {
        memset (kaddr, 0, PGSIZE);
    }
    return true;
}