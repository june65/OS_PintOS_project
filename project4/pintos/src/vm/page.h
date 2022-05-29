#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "vm/swap.h"
#include <hash.h>
#include "filesys/off_t.h"

enum page_status {
  ALL_ZERO,         
  ON_FRAME,        
  ON_SWAP,        
  FROM_FILESYS      
};

struct page_table
  {
    struct hash page_map;
  };

struct page_entry
  {
    void *upage;              
    void *kpage;            
    struct hash_elem elem;

    enum page_status status;

    bool dirty;           

    swap_index_t swap_index;  
    struct file *file;
    off_t file_offset;
    uint32_t read_bytes, zero_bytes;
    bool writable;
  };



struct page_table*supplemental_create (void);
void supplemental_destroy (struct page_table *);

bool supplemental_install_frame (struct page_table *supt, void *upage, void *kpage);
bool supplemental_install_zeropage (struct page_table *supt, void *);
bool supplemental_set_swap (struct page_table *supt, void *, swap_index_t);
bool supplemental_install_filesys (struct page_table *supt, void *page,
    struct file * file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

struct page_entry* supplemental_lookup (struct page_table *supt, void *);
bool supplemental_has_entry (struct page_table *, void *page);

bool supplemental_set_dirty (struct page_table *supt, void *, bool);

bool vm_load_page(struct page_table *supt, uint32_t *pagedir, void *upage);

bool supplemental_mm_unmap(struct page_table *supt, uint32_t *pagedir,
    void *page, struct file *f, off_t offset, size_t bytes);

void vm_pin_page(struct page_table *supt, void *page);
void vm_unpin_page(struct page_table *supt, void *page);

#endif

