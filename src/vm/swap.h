#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

/* 스왑 시스템 초기화 */
void swap_init (void);

/* 메모리 내용(kaddr)을 스왑 디스크로 내보내고, 저장된 슬롯 인덱스를 반환 */
size_t swap_out (void *kaddr);

/* 스왑 디스크의 슬롯(used_index)에 있는 데이터를 메모리(kaddr)로 읽어들임 */
void swap_in (size_t used_index, void *kaddr);

/* 해당 스왑 슬롯을 비움 (데이터를 버릴 때 사용) */
void swap_free (size_t used_index);

#endif