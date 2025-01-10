DDNET_PROTOCOL = ddnet_protocol/src
KVERSION = $(shell uname -r)

obj-m = nodummies.o
nodummies-objs = main.o common.o $(DDNET_PROTOCOL)/token.o $(DDNET_PROTOCOL)/packet.o
nodummies-objs += $(DDNET_PROTOCOL)/huffman.o $(DDNET_PROTOCOL)/fetch_chunks.o $(DDNET_PROTOCOL)/control_message.o
nodummies-objs += $(DDNET_PROTOCOL)/message.o $(DDNET_PROTOCOL)/chunk.o $(DDNET_PROTOCOL)/packer.o
ccflags-y += -I$(src)/ddnet_protocol/include/ddnet_protocol

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
install:
	insmod nodummies.ko
rm:
	rmmod nodummies
re:
	make rm
	make install
