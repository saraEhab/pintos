#include "threads/synch.h"
#include <stdio.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define ERROR -1
#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2
#define CLOSE_ALL -1

struct child_process {
    struct list_elem elem;
    int pid;
    int load;
    bool wait;
    bool exit;
    int status;

};

struct child_process *add_child_process(int pid);

struct child_process *get_child_process(int pid);

void remove_child_process(struct child_process *cp);

void syscall_init(void);

#endif /* userprog/syscall.h */
