#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define UDP_HLEN 8

void hex_dump(uint8_t *data, size_t len) {
    size_t rowsize = 16, li = 0, remaining = len, linelen;

    for (size_t i = 0, l = 0; i < len; i += rowsize) {
        printk("%06ld\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            printk(KERN_CONT "%02X ", (uint32_t) data[l]);
        }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");
    }
}

struct packet_type handler;

static int packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *og_dev) {
    if (ip_hdr(skb)->protocol == IPPROTO_UDP) {
        // That's little bit of magic because ethernet header is before data pointer?
        uint8_t *data = skb->data + ip_hdr(skb)->ihl * 4 + UDP_HLEN;
        // UDP's len includes header size
        size_t len = ntohs(udp_hdr(skb)->len) - UDP_HLEN;

        printk("UDP payload:\n");
        hex_dump(data, len);
    }

    kfree_skb(skb);
    return 0;
}

static int __init nodummies_start(void) {
    handler.type = htons(ETH_P_IP);
    handler.dev = NULL;
    handler.func = packet_rcv;

    dev_add_pack(&handler);

    return 0;
}

static void __exit nodummies_end(void) {
    printk(KERN_INFO "Bye, world!");

    dev_remove_pack(&handler);
}

module_init(nodummies_start);
module_exit(nodummies_end);

MODULE_LICENSE("GPL");
