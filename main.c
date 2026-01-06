#include <ddnet_protocol/control_message.h>
#include <ddnet_protocol/fetch_chunks.h>
#include <ddnet_protocol/huffman.h>
#include <ddnet_protocol/message.h>
#include <ddnet_protocol/packet.h>
#include <ddnet_protocol/token.h>

#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/udp.h>

#define UDP_HLEN 8
#define CLIENTS_LEN 16

struct client {
	pid_t pid;
	uint16_t main;
	uint16_t dummy;
};

struct packet {
	uint8_t buf[DDPROTO_MAX_PACKET_SIZE];
	uint8_t *cur;
	bool had_input;
};

struct client clients[CLIENTS_LEN];
struct packet_type handler;
struct kprobe kprobe = {
	.symbol_name = "do_exit",
};

static void on_message(void *ctx, DDProtoChunk *chunk) {
	struct packet *packet = ctx;

	if(chunk->payload.kind == DDPROTO_MSG_KIND_INPUT) {
		int32_t dir = chunk->payload.msg.input.direction;

		if(dir == 1) {
			chunk->payload.msg.input.direction = -1;
		} else if(dir == -1) {
			chunk->payload.msg.input.direction = 1;
		}

		if(packet->had_input == false) {
			packet->had_input = true;
		}
	}

	packet->cur += ddproto_encode_chunk_header(&chunk->header, packet->cur);
	DDProtoError err = DDPROTO_ERR_NONE;
	packet->cur += ddproto_encode_message(chunk, packet->cur, &err);
}

static int packet_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *og_dev) {
	if(eth_hdr(skb)->h_proto == htons(ETH_P_IP) && ip_hdr(skb)->protocol == IPPROTO_UDP && skb->pkt_type == PACKET_OUTGOING) {
		struct iphdr *iph = ip_hdr(skb);
		struct udphdr *udph = (struct udphdr *)((uint8_t *)iph + iph->ihl * 4); // calculate the udp header by hand because `udp_hdr` function returns the same pointer as `ip_hdr`
		uint8_t *data = (uint8_t *)udph + UDP_HLEN;
		size_t len = skb->len - (data - skb->data);

		if(len < DDPROTO_PACKET_HEADER_SIZE || len > DDPROTO_MAX_PACKET_SIZE) {
			goto end;
		}

		DDProtoPacketHeader header = ddproto_decode_packet_header(data);
		uint8_t payload[DDPROTO_MAX_PACKET_SIZE];
		DDProtoError err = DDPROTO_ERR_NONE;
		size_t payload_len = ddproto_get_packet_payload(&header, data, len, payload, sizeof(payload), &err);
		if(err != DDPROTO_ERR_NONE) {
			goto end;
		}

		if(header.flags & DDPROTO_PACKET_FLAG_CONTROL) {
			DDProtoControlMessage message;
            size_t size = ddproto_decode_control(payload, payload_len, &message, &err);
			if(err != DDPROTO_ERR_NONE || message.kind != DDPROTO_CTRL_MSG_CONNECT) {
				goto end;
			}

            header.token = ddproto_read_token(payload + size);

			for(size_t i = 0; i < CLIENTS_LEN; i++) {
                // second condition is there because connect control message is
                // sent every 500ms
				if(clients[i].pid == current->pid && clients[i].main != udph->source) {
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
		} else if(!(header.flags & DDPROTO_PACKET_FLAG_CONNLESS)) {
			for(size_t i = 0; i < CLIENTS_LEN; i++) {
				if(clients[i].pid == current->pid && clients[i].dummy == udph->source) {
					struct packet packet = {
						.had_input = false,
					};
					packet.cur = packet.buf;
                    DDProtoError err = DDPROTO_ERR_NONE;
					size_t size = ddproto_fetch_chunks(payload, payload_len, &header, on_message, &packet, &err);
                    if(err != DDPROTO_ERR_NONE) {
                        goto end;
                    }

                    header.token = ddproto_read_token(payload + size);
					ddproto_write_token(header.token, packet.cur);
					packet.cur += sizeof(DDProtoToken);

					if(packet.had_input) {
						ddproto_encode_packet_header(&header, data);
						data += DDPROTO_PACKET_HEADER_SIZE;

						if(header.flags & DDPROTO_PACKET_FLAG_COMPRESSION) {
							DDProtoError err = DDPROTO_ERR_NONE;
							ddproto_huffman_compress(packet.buf, packet.cur - packet.buf, data, len - DDPROTO_PACKET_HEADER_SIZE, &err);
						} else {
							memcpy(data, packet.buf, packet.cur - packet.buf);
						}
					}
				}
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
