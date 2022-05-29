#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#ifndef VM
#define frame_aloc(x, y) palloc_get_page(x)
#define frame_free(x) palloc_free_page(x)
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void push_arguments (const char *[], int cnt, void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

void parse_filename(char *src, char *dest) {
  int i;
  strlcpy(dest, src, strlen(src) + 1);
  for (i=0; dest[i]!='\0' && dest[i] != ' '; i++);
  dest[i] = '\0';
}

pid_t
process_execute (const char *cmdline)
{
  char *cmdline_copy = NULL, *file_name = NULL;
  char *save_ptr = NULL;
  struct process_control_block *pcb = NULL;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  cmdline_copy = palloc_get_page (0);
  if (cmdline_copy == NULL) {
    goto execute_failed;
  }
  strlcpy (cmdline_copy, cmdline, PGSIZE);

  file_name = palloc_get_page (0);
  if (file_name == NULL) {
    goto execute_failed;
  }
  strlcpy (file_name, cmdline, PGSIZE);
  file_name = strtok_r(file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */

  pcb = palloc_get_page(0);
  if (pcb == NULL) {
    goto execute_failed;
  }


  pcb->pid = PID_INITIALIZING;

  pcb->cmdline = cmdline_copy;
  pcb->waiting = false;
  pcb->exited = false;
  pcb->orphan = false;
  pcb->exitcode = -1;

  sema_init(&pcb->sema_initialization, 0);
  sema_init(&pcb->sema_wait, 0);

  tid = thread_create (file_name, PRI_DEFAULT, start_process, pcb);

  if (tid == TID_ERROR) {
    goto execute_failed;
  }

  sema_down(&pcb->sema_initialization);
  if(cmdline_copy) {
    palloc_free_page (cmdline_copy);
  }

  if(pcb->pid >= 0) {
    list_push_back (&(thread_current()->child_list), &(pcb->elem));
  }

  palloc_free_page (file_name);
  return pcb->pid;

execute_failed:
  if(cmdline_copy) palloc_free_page (cmdline_copy);
  if(file_name) palloc_free_page (file_name);
  if(pcb) palloc_free_page (pcb);

  return PID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *pcb_)
{
  struct thread *t = thread_current();
  struct process_control_block *pcb = pcb_;

  char *file_name = (char*) pcb->cmdline;
  bool success = false;

  const char **cmdline_tokens = (const char**) palloc_get_page(0);

  if (cmdline_tokens == NULL) {
    goto finish_step;
  }

  char* token;
  char* save_ptr;
  int cnt = 0;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
      token = strtok_r(NULL, " ", &save_ptr))
  {
    cmdline_tokens[cnt++] = token;
  }

  /* Initialize interrupt frame and load executable. */
  struct intr_frame if_;
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  if (success) {
    push_arguments (cmdline_tokens, cnt, &if_.esp);
  }
  palloc_free_page (cmdline_tokens);


finish_step:

  pcb->pid = success ? (pid_t)(t->tid) : PID_ERROR;
  t->pcb = pcb;

  sema_up(&pcb->sema_initialization);

  /* If load failed, quit. */
  if (!success)
    exit (-1);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct thread *t = thread_current ();
  struct list *child_list = &(t->child_list);
  struct process_control_block *child_pcb = NULL;
  struct list_elem *it = NULL;

  if (!list_empty(child_list)) {
    for (it = list_front(child_list); it != list_end(child_list); it = list_next(it)) {
      struct process_control_block *pcb = list_entry(
          it, struct process_control_block, elem);

      if(pcb->pid == child_tid) {
        child_pcb = pcb;
        break;
      }
    }
  }
  if (child_pcb == NULL) {
    return -1;
  }

  if (child_pcb->waiting) {
    return -1;
  }
  else {
    child_pcb->waiting = true;
  }

  if (! child_pcb->exited) {
    sema_down(& (child_pcb->sema_wait));
  }
  list_remove (it);

  int retcode = child_pcb->exitcode;

  palloc_free_page(child_pcb);

  return retcode;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct list *fdlist = &cur->file_descriptors;
  while (!list_empty(fdlist)) {
    struct list_elem *e = list_pop_front (fdlist);
    struct file_desc *desc = list_entry(e, struct file_desc, elem);
    file_close(desc->file);
    palloc_free_page(desc);
  }
#ifdef VM
  struct list *mmlist = &cur->mmap_list;
  while (!list_empty(mmlist)) {
    struct list_elem *e = list_begin (mmlist);
    struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
    ASSERT( munmap (desc->id) == true );
  }
#endif
  struct list *child_list = &cur->child_list;
  while (!list_empty(child_list)) {
    struct list_elem *e = list_pop_front (child_list);
    struct process_control_block *pcb;
    pcb = list_entry(e, struct process_control_block, elem);
    if (pcb->exited == true) {
      palloc_free_page (pcb);
    } else {
      pcb->orphan = true;
    }
  }

  if(cur->executing_file) {
    file_allow_write(cur->executing_file);
    file_close(cur->executing_file);
  }
  cur->pcb->exited = true;
  bool cur_orphan = cur->pcb->orphan;
  sema_up (&cur->pcb->sema_wait);
  if (cur_orphan) {
    palloc_free_page (& cur->pcb);
  }

#ifdef VM
  supplemental_destroy (cur->supt);
  cur->supt = NULL;
#endif
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
#ifdef VM
  t->supt = supplemental_create ();
#endif

  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  file_deny_write (file);
  thread_current()->executing_file = file;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;
  
  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
      struct thread *curr = thread_current ();
      ASSERT (pagedir_get_page(curr->pagedir, upage) == NULL);

      if (! supplemental_install_filesys(curr->supt, upage,
            file, ofs, page_read_bytes, page_zero_bytes, writable) ) {
        return false;
      }
#else
      /* Get a page of memory. */
      uint8_t *kpage = frame_aloc(PAL_USER, upage);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          frame_free (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          frame_free (kpage);
          return false; 
        }
#endif

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += PGSIZE;
#endif
    }
  return true;
}


static void
push_arguments (const char* cmdline_tokens[], int argc, void **esp)
{
  ASSERT(argc >= 0);

  int i, len = 0;
  void* argv_addr[argc];
  for (i = 0; i < argc; i++) {
    len = strlen(cmdline_tokens[i]) + 1;
    *esp -= len;
    memcpy(*esp, cmdline_tokens[i], len);
    argv_addr[i] = *esp;
  }

  *esp = (void*)((unsigned int)(*esp) & 0xfffffffc);

  *esp -= 4;
  *((uint32_t*) *esp) = 0;

  for (i = argc - 1; i >= 0; i--) {
    *esp -= 4;
    *((void**) *esp) = argv_addr[i];
  }

  *esp -= 4;
  *((void**) *esp) = (*esp + 4);

  *esp -= 4;
  *((int*) *esp) = argc;

  *esp -= 4;
  *((int*) *esp) = 0;

}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = frame_aloc (PAL_USER | PAL_ZERO, PHYS_BASE - PGSIZE);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        frame_free (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  bool success = (pagedir_get_page (t->pagedir, upage) == NULL);
  success = success && pagedir_set_page (t->pagedir, upage, kpage, writable);
#ifdef VM
  success = success && supplemental_install_frame (t->supt, upage, kpage);
  if(success) vm_frame_unpin(kpage);
#endif
  return success;
}

void construct_esp(char *file_name, void **esp) {

  char ** argv;
  int argc;
  int total_len;
  char stored_file_name[256];
  char *token;
  char *last;
  int i;
  int len;
  
  strlcpy(stored_file_name, file_name, strlen(file_name) + 1);
  token = strtok_r(stored_file_name, " ", &last);
  argc = 0;
  /* calculate argc */
  while (token != NULL) {
    argc += 1;
    token = strtok_r(NULL, " ", &last);
  }
  argv = (char **)malloc(sizeof(char *) * argc);
  /* store argv */
  strlcpy(stored_file_name, file_name, strlen(file_name) + 1);
  for (i = 0, token = strtok_r(stored_file_name, " ", &last); i < argc; i++, token = strtok_r(NULL, " ", &last)) {
    len = strlen(token);
    argv[i] = token;

  }

  /* push argv[argc-1] ~ argv[0] */
  total_len = 0;
  for (i = argc - 1; 0 <= i; i --) {
    len = strlen(argv[i]);
    *esp -= len + 1;
    total_len += len + 1;
    strlcpy(*esp, argv[i], len + 1);
    argv[i] = *esp;
  }
  /* push word align */
  *esp -= total_len % 4 != 0 ? 4 - (total_len % 4) : 0;
  /* push NULL */
  *esp -= 4;
  **(uint32_t **)esp = 0;
  /* push address of argv[argc-1] ~ argv[0] */
  for (i = argc - 1; 0 <= i; i--) {
    *esp -= 4;
    **(uint32_t **)esp = argv[i];
  }
  /* push address of argv */
  *esp -= 4;
  **(uint32_t **)esp = *esp + 4;

  /* push argc */
  *esp -= 4;
  **(uint32_t **)esp = argc;
  
  /* push return address */
  *esp -= 4;
  **(uint32_t **)esp = 0;
  free(argv);
}
