#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init nodummies_start(void) {
    printk(KERN_INFO "Hello, world!");

    return 0;
}

static void __exit nodummies_end(void) {
    printk(KERN_INFO "Bye, world!");
}

module_init(nodummies_start);
module_exit(nodummies_end);

MODULE_LICENSE("GPL");
