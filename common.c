#include <linux/module.h>
#include <linux/slab.h>

void *malloc(size_t size) {
	return kmalloc(size, GFP_USER);
}

void free(void *ptr) {
	kfree(ptr);
}
