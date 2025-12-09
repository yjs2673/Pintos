#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>
#include <bitmap.h>

/* This library provides data structures for the page replacement
   concepts (a.k.a Swapping). We will use a LRU(Least Recently Used)
   policy for this implementation.
   And note that this 'swap' library will work with 'frame' header file
   in the same directory. Various functions in both libraries will be
   used for performing the second chance (clock) algorithm in this pintOS.

   * You should first allocate a swap disk in the 'vm/build' directory
     by 'pintos-mkdisk swap.dsk --swap-size=n' instruction.
  -> swap.dsk will be automatically attached to the hdb1 while booting.

   * Note that the difference between 'frame' and 'swap' is, functions
     in the 'frame.h' manage the frame table by performing list operations.

     In the contrast, functions in 'swap.h' manage the swap table, with
     'actually' accessing to and working on the swap disk, by using the
     evicted(on LRU) frame prodived from the frame table of 'frame.h'    */

/* Bitmap indicates the 'freed or allocated' info.
   That is, it represents the status of the swap table. */
#define OFS_ZERO 0x00      /* Starting offset of the block structure. */
#define OFS_MAX 0x08       /* Maximum offset of the block structure. */
extern struct bitmap *swap_bitmap;

/* These only four functions are interfaces of this header.
   swap_init should be called in the beginning of the system,
   and the other three will be used in the frame management.
   (That is, main user(customer) of this header is 'frame.c') */
void swap_init (void);
void swap_free (size_t index);
size_t swap_out (void *kaddr);
void swap_in (size_t index, void *kaddr);

#endif
