#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "lib/kernel/hash.h"

#include "threads/synch.h"
#include "threads/palloc.h"


void frame_in (void);
void* frame_aloc (enum palloc_flags flags, void *upage);

void frame_free (void*);
void frame_entry_remove (void*);

void frame_pin (void* kpage);
void frame_unpin (void* kpage);

#endif 

