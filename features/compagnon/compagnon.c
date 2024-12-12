#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marouane");
MODULE_DESCRIPTION("Un module noyau pour exécuter un fichier c'est un #compagnon");

static int __init exec_file_init(void)
{
    const char *file_path = "/111111111111111111111111111/trigger";  // Le chemin du fichier à exécuter
    char *argv[] = { (char *)file_path, NULL };  // Arguments pour l'exécution
    char *envp[] = { NULL };  // Variables d'environnement

    printk(KERN_INFO "Module noyau chargé, tentative d'exécution du fichier : %s\n", file_path);

    // Exécuter le fichier avec call_usermodehelper
    int ret = call_usermodehelper(file_path, argv, envp, UMH_WAIT_PROC);

    if (ret) {
        printk(KERN_ERR "Erreur lors de l'exécution du fichier : %d\n", ret);
    } else {
        printk(KERN_INFO "Le fichier a été exécuté avec succès.\n");
    }

    return 0;
}

static void __exit exec_file_exit(void)
{
    printk(KERN_INFO "Module noyau déchargé.\n");
}

module_init(exec_file_init);
module_exit(exec_file_exit);
