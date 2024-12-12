#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>

static struct kprobe kp;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // Access the third argument of the getdents64 syscall on x86_64
    unsigned long count = ((struct pt_regs*)regs->di)->dx;
    printk("kprobe: getdents64 called with count = %ld\n", count);
    return 0;
}


static int __init kprobe_init(void)
{
    kp.pre_handler = handler_pre;
    kp.symbol_name = "__x64_sys_getdents64";

    if (register_kprobe(&kp) < 0) {
        printk("register_kprobe failed\n");
        return -1;
    }
    printk("kprobe registered\n");
    return 0;
}


static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk("kprobe unregistered\n");
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
