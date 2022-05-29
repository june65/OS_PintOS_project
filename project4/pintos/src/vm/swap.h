#ifndef VM_SWAP_H
#define VM_SWAP_H

typedef uint32_t swap_index_t;

void swap_init (void);

swap_index_t swap_out (void *page);

void swap_in (swap_index_t swap_index, void *page);

void swap_free (swap_index_t swap_index);


#endif 

