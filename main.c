#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/udp.h>

#include <control_message.h>
#include <packet.h>

#define UDP_HLEN 8
#define CLIENTS_LEN 16

struct client {
	pid_t pid;
	uint16_t main;
	uint16_t dummy;
};

struct client clients[CLIENTS_LEN];
struct packet_type handler;
struct kprobe kprobe = {
	.symbol_name = "do_exit",
};

static int packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *og_dev) {
	if(eth_hdr(skb)->h_proto == htons(ETH_P_IP) && ip_hdr(skb)->protocol == IPPROTO_UDP && skb->pkt_type == PACKET_OUTGOING) {
		struct iphdr *iph = ip_hdr(skb);
		struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + iph->ihl * 4); // calculate the udp header by hand because `udp_hdr` function returns the same pointer as `ip_hdr`
		uint8_t *data = (uint8_t *)udph + UDP_HLEN;
		size_t len = skb->len;

		if(len < PACKET_HEADER_SIZE || len > MAX_PACKET_SIZE) {
			goto end;
		}

		PacketHeader header = decode_packet_header(data);

		if(!(header.flags & PACKET_FLAG_CONTROL)) {
			goto end;
		}

		uint8_t payload[MAX_PACKET_SIZE];
		Error err = ERR_NONE;
		size_t payload_len = get_packet_payload(&header, data, len, payload, sizeof(payload), &err);
		if(err != ERR_NONE) {
			goto end;
		}

		ControlMessage message = decode_control(payload, payload_len, &header, &err);
		if(err != ERR_NONE || message.kind != CTRL_MSG_CONNECT) {
			goto end;
		}

		for(size_t i = 0; i < CLIENTS_LEN; i++) {
			if(clients[i].pid == current->pid) {
				clients[i].dummy = udph->source;

				goto end;
			}
		}

		for(size_t i = 0; i < CLIENTS_LEN; i++) {
			if(clients[i].pid == 0) {
				clients[i].pid = current->pid;
				clients[i].main = udph->source;

				goto end;
			}
		}
	}

end:
	kfree_skb(skb);
	return 0;
}

static int __kprobes handler_pre(struct kprobe *kp, struct pt_regs *regs) {
	for(size_t i = 0; i < CLIENTS_LEN; i++) {
		if(clients[i].pid == current->pid) {
			clients[i] = (struct client){};

			break;
		}
	}

	return 0;
}

static int __init nodummies_start(void) {
	handler.type = htons(ETH_P_ALL); // for some reason ETH_P_IP doesn't give outgoing packets >:(
	handler.dev = NULL;
	handler.func = packet_rcv;

	kprobe.pre_handler = handler_pre;
	kprobe.post_handler = NULL;

	int ret = register_kprobe(&kprobe);
	if(ret < 0) {
		printk("register_kprobe failed: %d\n", ret);

		return ret;
	}

	dev_add_pack(&handler);
	printk("nodummies: started\n");

	return 0;
}

static void __exit nodummies_end(void) {
	unregister_kprobe(&kprobe);
	dev_remove_pack(&handler);
	printk("nodummies: exited\n");
}

module_init(nodummies_start);
module_exit(nodummies_end);

MODULE_LICENSE("GPL");
