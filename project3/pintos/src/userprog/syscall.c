#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
void argument_to_kernel (void *esp, int *argv, int argc);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int32_t argv[4];
  switch (*(uint32_t *)(f->esp)) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      argument_to_kernel(f->esp,argv,1);
      exit((int)argv[0]);
      break;
    case SYS_EXEC:
      argument_to_kernel(f->esp,argv,1);
      f -> eax = exec((int)argv[0]);
      break;
    case SYS_WAIT:
      argument_to_kernel(f->esp,argv,1);
      f -> eax = wait((int)argv[0]);
      break;
    case SYS_CREATE:
      argument_to_kernel(f->esp,argv,2);		
      f->eax = create((const char*)argv[0],(unsigned)argv[1]);
      break;
    case SYS_REMOVE:
      argument_to_kernel(f->esp,argv,1);
      f->eax = remove((const char*)argv[0]);
      break;
    case SYS_OPEN:
      break;
    case SYS_FILESIZE:
      break;
    case SYS_READ:
      argument_to_kernel(f->esp,argv,3);
      f->eax = read((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_WRITE:
      argument_to_kernel(f->esp,argv,3);
      f->eax = write((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_SEEK:
      break;
    case SYS_TELL:
      break;
    case SYS_CLOSE:
      break;
  }

  //thread_exit ();
}
void halt (void) {
  shutdown_power_off();
}

void exit (int status) {
  struct thread* cur = thread_current();
  printf("%s: exit(%d)\n", thread_name(), status);
  cur->exit_status = status;
  thread_exit ();
}

pid_t exec (const char *cmd_line) {
  return process_execute(cmd_line);
}

int wait (pid_t pid) {
  return process_wait(pid);
}

int read (int fd, void* buffer, unsigned size) {
  int i;
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
  }
  return i;
}

int write (int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  return -1; 
}

bool create(const char *file, unsigned initial_size) {
  return filesys_create (file,initial_size);
}

bool remove(const char *file) {
  return filesys_remove(file);
}

void is_valid_address(void *addr)
{
  if(!is_user_vaddr(addr))
  {
    exit(-1);
  }
}

void argument_to_kernel (void *esp, int *argv, int argc) {
  int address = 0;
  esp = esp + 4;
  while(argc > 0) {
     argc--;
     is_valid_address(esp);
     argv[address] = *(int*)esp;
     esp = esp + 4;
     address++;
  }
}


