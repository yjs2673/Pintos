#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <list.h>
#include "filesys/file.h"

/* This header file includes crucial data structures for the memory
   mapping routines of this pintOS system, and implements interfaces
   such as mmap() and munmap(). */

/* Mapping Identifier type. Note that 'mapid_t' is declared both in
   here and 'userprog/syscall.h'. It doesn't matter cause it's just uint. */
typedef unsigned mapid_t;

/* Data structures for the implementation of the mmap() system call.
   Note that the call for mmap()/munmap() takes place in 'syscall.c' file
   in the userprog directory. In here, the structure declaration and the
   implementation of the memory mapping procedures take place. */
struct mm_entry
{
  /* Mapping Identifier. */
  mapid_t mapid;

  /* Pointer for the mapped file. */
  struct file *file;

  /* List of corresponding pages about mapping. */
  struct list pte_list;

  /* Iterator for the mmap data list. */
  struct list_elem elem;
};

/* MMAP_ERROR: indicates that an error occurs in the 'mmap' syscall */
#define MMAP_ERROR -1

/* These two functions work as mmap() and munmap() respectively. */
mapid_t mm_mapping (int fd, void *addr);
void mm_freeing (mapid_t mapid);

/* Macros for raising a readability of codes. 
   - VALIDATION: Checks whether there're a corresponding page offset, 
     the NULLity, is_from_kernel_area?, is_already_paged?. */
#define VALIDATION(addr) (pg_ofs(addr)!=0||!addr||!is_user_vaddr(addr)||pt_find_entry(addr))

#endif
