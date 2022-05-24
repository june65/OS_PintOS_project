#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/vaddr.h"

#define VM_BIN  0   /* binary file data load */
#define VM_FILE 1   /* mapped file data load */
#define VM_ANON 2   /* swap file data load */

struct vm_entry {
    uint8_t type;   /* which type of vm */
    void *virtual_address; /* vm_entry virtual page */
    bool valid_write;
    bool is_load;

    struct list_elem mmap_elem;

    struct file *f;
    size_t offset;
    size_t read_bytes;
    size_t fill_page_zero;

    size_t swap_segment;
    struct hash_elem elem;
}

void vm_init (struct hash *vm);
static unsigned vm_hash_func(const struct hash_elem *elem void *aux);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux );
bool insert_vm_entry(struct hash *vm, struct vm_entry *insert_entry);
bool delete_vm_entry(struct hash *vm, struct vm_entry *delete_entry);
struct vm_entry *find_vm_entry(void *virtual_address);