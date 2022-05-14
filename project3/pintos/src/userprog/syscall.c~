#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
void argument_to_kernel (void *esp, int *argv, int argc);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
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
      is_valid_address((void*)argv[0]);
      f->eax = create((const char*)argv[0],(unsigned)argv[1]);
      break;
    case SYS_REMOVE:
      argument_to_kernel(f->esp,argv,1);
      is_valid_address((void*)argv[0]);
      f->eax = remove((const char*)argv[0]);
      break;
    case SYS_OPEN:
      argument_to_kernel(f->esp, argv, 1);
      is_valid_address((void*)argv[0]);
      f->eax = open ((const char*)argv[0]);
      break;
    case SYS_FILESIZE:
      argument_to_kernel(f->esp,argv,1);
      f->eax=filesize((int)argv[0]);
      break;
    case SYS_READ:
      argument_to_kernel(f->esp,argv,3);
      is_valid_address((void*)argv[1]);
      f->eax = read((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_WRITE:
      argument_to_kernel(f->esp,argv,3);
      f->eax = write((int)argv[0], (void*)argv[1], (unsigned)argv[2]);
      break;
    case SYS_SEEK:
      argument_to_kernel(f->esp,argv,2);
      seek((int)argv[0], (unsigned)argv[1]);
      break;
    case SYS_TELL:
      argument_to_kernel(f->esp,argv,1);
      f->eax = tell((int)argv[0]);
      break;
    case SYS_CLOSE:
      argument_to_kernel(f->esp,argv,1);
      close((int)argv[0]);
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

int read (int num_fd, void* buffer, unsigned size) {
  is_valid_address(buffer);
  struct thread * cur = thread_current();
  int len_read = 0;
  lock_acquire(&filesys_lock);
  int i;
  if (num_fd == 0) {
    for (i = 0; i < size; i++) {
      ((char *)buffer)[i] = input_getc();
      len_read++;
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
  }
  else {
    struct file *f = cur->fd[num_fd];
    if(f != NULL) {
      
      len_read = file_read(f,buffer,size);
    }
  }
  lock_release(&filesys_lock);
  return len_read;
}


int write (int num_fd, const void *buffer, unsigned size) {
  is_valid_address(buffer);
  struct thread * cur = thread_current();
  int len_write = 0;
  lock_acquire(&filesys_lock);
  if (num_fd == 1) {
    putbuf(buffer, size);
    len_write = size;
  }
  else {
    struct file *f = cur->fd[num_fd];
    if(f!=NULL) {
      len_write = file_write(f,buffer,size);
    }
  }
  lock_release(&filesys_lock);
  return len_write;
}

bool create(const char *file, unsigned initial_size) {
  if (file == NULL) {
      exit(-1);
  }
  return filesys_create (file,initial_size);
}

bool remove(const char *file) {
  return filesys_remove(file);
}

int open (const char *file) {
  int i;
  is_valid_address(file);
  struct file * f = NULL;
  struct thread * cur = thread_current();
  if(file == NULL) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  f = filesys_open(file);
  if(f == NULL) {
    lock_release(&filesys_lock);
    return -1;
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        if (strcmp(thread_current()->name, file) == 0) {
            file_deny_write(f);
        }   
        thread_current()->fd[i] = f; 
        lock_release(&filesys_lock);
        return i;
      }   
    }   
  }
  lock_release(&filesys_lock);
  return -1;
}

int filesize(int num_fd) {
  struct thread * cur = thread_current();
  struct file * f = cur->fd[num_fd];
  if(f == NULL) {
    return -1;
  }
  return file_length(f);
}

void seek (int num_fd, unsigned position) {
  if (thread_current()->fd[num_fd] == NULL) {
    exit(-1);
  }
  file_seek(thread_current()->fd[num_fd], position);
}

unsigned tell (int num_fd) {
  if (thread_current()->fd[num_fd] == NULL) {
    exit(-1);
  }
  return file_tell(thread_current()->fd[num_fd]);
}

void close (int num_fd) {
  struct file* fp;
  if (thread_current()->fd[num_fd] == NULL) {
    exit(-1);
  }
  fp = thread_current()->fd[num_fd];
  thread_current()->fd[num_fd] = NULL;
  return file_close(fp);
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


