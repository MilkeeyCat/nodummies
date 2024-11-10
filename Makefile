obj-m = nodummies.o
nodummies-objs = main.o malloc.o ddnet_protocol/src/token.o ddnet_protocol/src/packet.o ddnet_protocol/src/control_packet.o
KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
