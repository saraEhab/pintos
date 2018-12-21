#include <stdbool.h>
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
#include "userprog/syscall.h"

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *) 0x08048000) /*VADDR : virtual address ,
 * this value is the last right value the virtual address can take*/


struct lock filesys_lock;


struct process_file {
    struct file *file;
    int fd;
    struct list_elem elem;
};

int process_add_file(struct file *f);

void check_valid_ptr(const void *vaddr);

void get_arg(struct intr_frame *f, int *arg, int n);

int user_to_kernel_ptr(const void *vaddr);

static void syscall_handler(struct intr_frame *);

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&filesys_lock);
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