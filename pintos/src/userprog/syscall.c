#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *) 0x08048000) /*VADDR : virtual address*/

int process_add_file(struct file *f);

void check_valid_ptr(const void *vaddr);

void get_arg(struct intr_frame *f, int *arg, int n);

int user_to_kernel_ptr(const void *vaddr);

static void syscall_handler(struct intr_frame *);

struct lock filesys_lock;

struct process_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};


void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/*handles system calls by terminating the process
 *It will need to return the system call number
 * and any system call arguments,
 * and carry out appropriate actions.*/
static void
syscall_handler(struct intr_frame *f UNUSED) {
    int arg[MAX_ARGS];
    check_valid_ptr((const void *) f->esp);
    switch (*(int *) f->esp) {
        case SYS_HALT:   /* Halt the operating system. */
            halt();
            break;

        case SYS_EXIT:   /* Terminate this process. */
            get_arg(f, &arg[0], 1);
            exit(arg[0]);
            break;

        case SYS_EXEC:  /* Start another process. */
            get_arg(f, &arg[0], 1);
            arg[0] = user_to_kernel_ptr((const void *) arg[0]);
            f->eax = exec((const char *) arg[0]);
            break;

        case SYS_WAIT:  /* Wait for a child process to die. */
            get_arg(f, &arg[0], 1);
            f->eax = wait(arg[0]);
            break;

        case SYS_CREATE:  /* Create a file. */
            get_arg(f, &arg[0], 2);
            arg[0] = user_to_kernel_ptr((const void *) arg[0]);
            f->eax = create((const char *) arg[0], (unsigned) arg[1]);
            break;

        case SYS_REMOVE: /* Delete a file. */
            get_arg(f, &arg[0], 1);
            arg[0] = user_to_kernel_ptr((const void *) arg[0]);
            f->eax = remove((const char *) arg[0]);
            break;

        case SYS_OPEN: /* Open a file. */
            get_arg(f, &arg[0], 1);
            arg[0] = user_to_kernel_ptr((const void *) arg[0]);
            f->eax = open((const char *) arg[0]);
            break;
        case SYS_FILESIZE:
            get_arg(f, &arg[0], 1);
            f->eax = filesize(arg[0]);
            break;
        case SYS_READ:
            get_arg(f, &arg[0], 3);
            check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
            break;
        case SYS_WRITE:
            get_arg(f, &arg[0], 3);
            check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
            arg[1] = user_to_kernel_ptr((const void *) arg[1]);
            f->eax = write(arg[0], (const void *) arg[1],
                           (unsigned) arg[2]);
            break;
        case SYS_SEEK:
            get_arg(f, &arg[0], 2);
            seek(arg[0], (unsigned) arg[1]);
            break;
        case SYS_TELL:
            get_arg(f, &arg[0], 1);
            f->eax = tell(arg[0]);
            break;
        case SYS_CLOSE:
            get_arg(f, &arg[0], 1);
            close(arg[0]);
            break;
    }
}
/*add a file to the current thread , whereas the thread has to know the number of files it opens*/
int process_add_file(struct file *fileStruct) {
    /*create and init new fd_element*/
    struct process_file *processFile = malloc(sizeof(struct process_file));
    processFile->file = fileStruct;
    processFile->fd = thread_current()->fd;
    thread_current()->fd++;
    /* add this fd_element to this thread fd_list*/
    list_push_back(&thread_current()->file_list, &processFile->elem);
    return processFile->fd;
}

/*terminates the pintos by calling a function shutdown_power_off
 * we don't use it a lot because it make the pintos lose some
 * information about the potential deadlocks */
void halt(void) {
    //defined in threads/init.c
    shutdown_power_off();
}

/*terminates the current user program
 * and return the status to the kernel
 * if there is a parent process waiting for it
 * the returned status will be 0 in success
 * ,non zero in fail*/
void exit(int status) {
    struct thread *currentThread = thread_current();
    //check if there is a parent waiting for it
    if (thread_alive(currentThread->parent)) {
        currentThread->cp->status = status;  /*set the status of the current process child*/
    }
    printf("%s: exit(%d)\n", currentThread->name, status);

    /* De schedules the current thread and destroys it.  Never
   returns to the caller. */
    thread_exit();
}


/*run the executable with name cmd_line
 * and pass the given arguments
 * return the id of the new process*/
/*parent process can't return form exec until
 * the child process successfully loaded its executable*/
pid_t exec(const char *cmd_line) {
    pid_t pid = process_execute(cmd_line);/* create child process to execute cmd*/
    struct child_process *cp = get_child_process(pid); /*get the created child*/
    ASSERT(cp);

    /*waiting for child process to load its executable*/
    while (cp->load == NOT_LOADED) {
        /*built in function in synch.h*/
        barrier();
    }
    /*child process's load fails*/
    if (cp->load == LOAD_FAIL) {
        return ERROR;
    }
    return pid;
}

/*take the pid for the child process that its parent will wait for
 * until its termination
 * returns the process exit status to its parent
 * returns-1 if the process was terminated by the kernel (error)*/
int wait(pid_t pid) {
    return process_wait(pid);
}

/*creates a new file called file ,
 * initial size in bytes
 * Returns true if successful,false otherwise.
 * Creating a new file does not open it:*/
bool create(const char *file, unsigned initial_size) {
    lock_acquire(&filesys_lock);
    bool createdSuccessfully = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return createdSuccessfully;
}

/*Deletes the file called file.
 * Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed,
 * and removing an open file does not close it. */
bool remove(const char *file) {
    lock_acquire(&filesys_lock);
    bool deletedSuccessfully = filesys_remove(file);
    lock_release(&filesys_lock);
    return deletedSuccessfully;
}

/*opens a file called file
 * returns a non negative integer handler "file descriptor"
 * if the file doesn't open it returns -1*/
int open(const char *file) {
    lock_acquire(&filesys_lock);
    struct file *fileStruct = filesys_open(file);
    /*the file doesn't open returns -1*/
    if (!fileStruct) {
        lock_release(&filesys_lock);
        return ERROR;
    }
    int fileDescriptor = process_add_file(fileStruct);
    lock_release(&filesys_lock);
    return fileDescriptor;
}
/* get the file*/
struct file* process_get_file (int fd)
{
    struct thread *t = thread_current();
    struct list_elem *e;

    for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
         e = list_next (e))
    {
        struct process_file *pf = list_entry (e, struct process_file, elem);
        if (fd == pf->fd)
        {
            return pf->file;
        }
    }
    return NULL;
}


/* first get the file
 * then calculate its size
 * if the file not found then error*/
int filesize (int fd)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f)
    {
        lock_release(&filesys_lock);
        return ERROR;
    }
    int size = file_length(f);
    lock_release(&filesys_lock);
    return size;
}

/*Reads size bytes from the file open as fd into buffer. Returns the number of bytes actually
read (0 at end of file), or -1 if the file could not be read (due to a condition other than end
of file). Fd 0 reads from the keyboard using input_getc().*/

int read (int fd, void *buffer, unsigned size)
{
    if (fd == 0)
    {
        unsigned i;
        uint8_t* local_buffer = (uint8_t *) buffer;
        for (i = 0; i < size; i++)
        {
            local_buffer[i] = input_getc();
        }
        return size;
    }
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f)
    {
        lock_release(&filesys_lock);
        return ERROR;
    }
    int bytes = file_read(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes;
}

/*Writes size bytes from buffer to the open file fd. Returns the number of bytes actually
written,Fd 1 writes to the console. Your code to write to the console should write all of buffer in
one call to putbuf()*/
int write (int fd, const void *buffer, unsigned size)
{
    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f)
    {
        lock_release(&filesys_lock);
        return ERROR;
    }
    int bytes = file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return bytes;
}

/*Changes the next byte to be read or written in open file fd to position, expressed in bytes
from the beginning of the file. (Thus, a position of 0 is the file's start.)*/
void seek (int fd, unsigned position)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f)
    {
        lock_release(&filesys_lock);
        return;
    }
    file_seek(f, position);
    lock_release(&filesys_lock);
}

/*Returns the position of the next byte to be read or written in open file fd, expressed in
bytes from the beginning of the file.*/
unsigned tell (int fd)
{
    lock_acquire(&filesys_lock);
    struct file *f = process_get_file(fd);
    if (!f)
    {
        lock_release(&filesys_lock);
        return ERROR;
    }
    off_t offset = file_tell(f);
    lock_release(&filesys_lock);
    return offset;
}

void process_close_file (int fd)
{
    struct thread *t = thread_current();
    struct list_elem *next, *e = list_begin(&t->file_list);

    while (e != list_end (&t->file_list))
    {
        next = list_next(e);
        struct process_file *pf = list_entry (e, struct process_file, elem);
        if (fd == pf->fd || fd == CLOSE_ALL)
        {
            file_close(pf->file);
            list_remove(&pf->elem);
            free(pf);
            if (fd != CLOSE_ALL)
            {
                return;
            }
        }
        e = next;
    }
}

/*Closes file descriptor fd. Exiting or terminating a process implicitly closes all its open file
descriptors, as if by calling this function for each one.*/
void close (int fd)
{
    lock_acquire(&filesys_lock);
    process_close_file(fd);
    lock_release(&filesys_lock);
}



/*check if all bytes within range are correct
 * for strings + buffers*/
/*checks if the given pointer
 * is a user virtual address or not
 * if not exit with error*/
void check_valid_ptr(const void *vaddr) {
    /*is_user_vaddr : Returns true if VADDR is a user virtual address.
     * second condition checks if the vaddr is within the range of the addresses*/
    if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM) {
        exit(ERROR);
    }
}

/*arg :is a pointer to the beginning of an array
 * that holds the arguments that will be passed to a system call function
 * n : no. of arguments that will be passed to a system call function
 * f : is the interrupt frame*/
/*for example : exec function takes 1 argument so n = 1
 * and the arg will be the 0 which is the first element in the array*/
void get_arg(struct intr_frame *f, int *arg, int n) {
    int i;
    int *ptr;
    for (i = 0; i < n; i++) {
        ptr = (int *) f->esp + i + 1;
        check_valid_ptr((const void *) ptr);
        arg[i] = *ptr;
    }
}

/*Returns the kernel virtual address
 * corresponding to that physical address, or a null pointer if
 * the parameter vaddr is unmapped*/
int user_to_kernel_ptr(const void *vaddr) {
    check_valid_ptr(vaddr);
/* void *pagedir_get_page (uint32_t *pd, const void *uaddr) :
 * Looks up the physical address that corresponds to user virtual
 * address UADDR in PD.  Returns the kernel virtual address
 * corresponding to that physical address, or a null pointer if
 * UADDR is unmapped. */
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (!ptr) {
        exit(ERROR);
    }
    return (int) ptr;
}

struct child_process *add_child_process(int pid) {
    struct child_process *cp = malloc(sizeof(struct child_process));
    cp->pid = pid;
    cp->load = NOT_LOADED;
    cp->wait = false;
    cp->exit = false;
    list_push_back(&thread_current()->child_list,
                   &cp->elem);
    return cp;
}

struct child_process *get_child_process(int pid) {
    struct thread *currentThread = thread_current();
    struct list_elem *e;

    for (e = list_begin(&currentThread->child_list); e != list_end(&currentThread->child_list);
         e = list_next(e)) {
        struct child_process *childProcess = list_entry(e,
        struct child_process, elem);
        if (pid == childProcess->pid) {
            return childProcess;
        }
    }
    return NULL;
}

/*remove the child process after finishing -> when return back to its parent*/
void remove_child_process(struct child_process *cp) {
    list_remove(&cp->elem);
    free(cp);
}

void check_valid_buffer (void* buffer, unsigned size)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      check_valid_ptr((const void*) local_buffer);
      local_buffer++;
    }
}
