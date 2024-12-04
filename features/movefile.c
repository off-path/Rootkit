#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/types.h>

static const char *src_path = "/root/lkm.ko";
static const char *dest_dir = "/111111111111111111111111111/";
static const char *dest_file = "lkm.ko";

static int move_file(void) {
    struct path src, dest_dir_path;
    struct dentry *dest_dentry;
    struct renamedata rename_data;
    int ret;

    // Résolution des chemins source
    ret = kern_path(src_path, LOOKUP_FOLLOW, &src);
    if (ret) {
        printk(KERN_ERR "Erreur: Impossible de trouver %s\n", src_path);
        return ret;
    }

    // Résolution du répertoire de destination
    ret = kern_path(dest_dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir_path);
    if (ret) {
        printk(KERN_ERR "Erreur: Impossible de trouver le répertoire %s\n", dest_dir);
        path_put(&src);
        return ret;
    }

    // Création de la dentry pour le fichier cible
    dest_dentry = d_alloc_name(dest_dir_path.dentry, dest_file);
    if (!dest_dentry) {
        printk(KERN_ERR "Erreur: Impossible de créer la dentry pour %s\n", dest_file);
        path_put(&src);
        path_put(&dest_dir_path);
        return -ENOMEM;
    }

    // Configuration des données pour vfs_rename
    rename_data.old_dir = d_inode(src.dentry->d_parent);
    rename_data.old_dentry = src.dentry;
    rename_data.new_dir = d_inode(dest_dir_path.dentry);
    rename_data.new_dentry = dest_dentry;
    rename_data.flags = 0;

    // Appel à vfs_rename
    ret = vfs_rename(&rename_data);
    if (ret) {
        printk(KERN_ERR "Erreur: Impossible de déplacer %s vers %s%s\n",
               src_path, dest_dir, dest_file);
    } else {
        printk(KERN_INFO "Fichier déplacé avec succès de %s à %s%s\n",
               src_path, dest_dir, dest_file);
    }

    // Libération des ressources
    dput(dest_dentry);
    path_put(&src);
    path_put(&dest_dir_path);
    return ret;
}

static int __init moovefile_init(void) {
    printk(KERN_INFO "Chargement du module moovefile\n");
    return move_file();
}

static void __exit moovefile_exit(void) {
    printk(KERN_INFO "Déchargement du module moovefile\n");
}

module_init(moovefile_init);
module_exit(moovefile_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("Module pour déplacer un fichier dans le noyau Linux");
