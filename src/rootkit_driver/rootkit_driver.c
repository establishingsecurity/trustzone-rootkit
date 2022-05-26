#include <linux/module.h>

MODULE_LICENSE("GPL");

char key[] = "-----BEGIN RSA PRIVATE KEY----- kernel-test-key -----END RSA PRIVATE KEY-----";

static int __init rootkit_driver_init(void) {
    printk(KERN_INFO "rootkit test module loaded\n");
    printk(KERN_INFO "key: %px %px\n", &key, virt_to_phys(&key));
    return 0;
}

module_init(rootkit_driver_init);
