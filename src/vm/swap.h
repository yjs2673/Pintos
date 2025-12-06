#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define BLOCK_MAX 8    

void swap_init(void);
void swap_in(size_t idx, void *paddr);
size_t swap_out(void *paddr);
void handle_block(size_t index, void* kaddr, bool r_w);



#endif