#include "vm/page.h"

void vm_init (struct hash *vm) {
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *vm = hash_entry(e, struct vm_entry, elem);
    return hash_int(vm->virtual_address);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
    struct vm_entry *vm_a = hash_entry(a, struct vm_entry, elem);
    struct vm_entry *vm_b = hash_entry(b, struct vm_entry, elem);
    bool less;
    less = vm_a->virtual_address < vm_b->virtual_address;
    return less;
}

static void destroy_vm_func(struct hash_elem *e, void *aux UNUSED) {
    struct vm_entry *destroy_entry = hash_entry(e, struct vm_entry, elem);
    free(destroy_entry);
}

bool insert_vm_entry(struct hash *vm, struct vm_entry *insert_entry) {
    if(hash_insert(vm, &(insert_entry->elem)) == NULL) {
        return true;
    }
    else {
        return false;
    }
}

bool delete_vm_entry(struct hash *vm, struct vm_entry *delete_entry) {
    if(hash_delete(vm,&(delete_entry->elem)) == NULL) {
        return false;
    }
    else {
        free(delete_entry);
        return true;
    }
}

struct vm_entry *find_vm_entry(void *virtual_address) {
    struct vm_entry find_entry;
    struct hash_elem *e;
    find_entry.virtual_address = pg_round_down(virtual_address);
    e = hash_find(&(thread_current()->vm), &(find_entry.elem));

    if(e != NULL) {
        return hash_entry(e,struct vm_entry, elem);
    }
    else {
        return NULL;
    }
}

void destroy_vm_entry(struct hash *vm) {
    hash_destroy(vm, destroy_vm_func);
}