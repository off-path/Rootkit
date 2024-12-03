#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/stat.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre nom");
MODULE_DESCRIPTION("Un LKM qui crée un dossier 111111111111111111111111111 à la racine.");

static int __init dir_init(void)
{
    struct path path;
    struct dentry *dentry;
    struct inode *dir_inode;
    int ret;

    printk(KERN_INFO "Chargement du module dir...\n");

    // Trouver le chemin de la racine ("/")
    ret = kern_path("/", 0, &path);
    if (ret) {
        printk(KERN_ERR "Erreur lors de l'accès au répertoire racine.\n");
        return ret;
    }

    // Obtenir l'inode du répertoire racine
    dir_inode = path.dentry->d_inode;

    // Créer la dentry pour "111111111111111111111111111"
    dentry = d_alloc_name(path.dentry, "111111111111111111111111111");
    if (!dentry) {
        printk(KERN_ERR "Erreur lors de la création de la dentry.\n");
        return -ENOMEM;
    }

    // Créer le répertoire "111111111111111111111111111" dans le répertoire racine
    ret = vfs_mkdir(NULL, dir_inode, dentry, S_IRWXU | S_IRWXG | S_IRWXO);
    if (ret) {
        printk(KERN_ERR "Erreur lors de la création du répertoire 111111111111111111111111111.\n");
        dput(dentry);  // Libération de la dentry en cas d'échec
        return ret;
    }

    printk(KERN_INFO "Répertoire '111111111111111111111111111' créé avec succès.\n");

    return 0;
}

static void __exit dir_exit(void)
{
    printk(KERN_INFO "Module dir déchargé.\n");
}

module_init(dir_init);
module_exit(dir_exit);
