DDNET_PROTOCOL = ddnet_protocol/src
KVERSION = $(shell uname -r)

# yoinked from https://github.com/torvalds/linux/blob/7f98ab9da046865d57c102fd3ca9669a29845f67/arch/x86/Makefile#L87-L90
CC_FLAGS_FPU := -msse -msse2
ifdef CONFIG_CC_IS_GCC
CC_FLAGS_FPU += -mhard-float
endif

obj-m = nodummies.o
nodummies-objs = main.o common.o $(DDNET_PROTOCOL)/token.o $(DDNET_PROTOCOL)/packet.o \
$(DDNET_PROTOCOL)/huffman.o $(DDNET_PROTOCOL)/fetch_chunks.o $(DDNET_PROTOCOL)/control_message.o \
$(DDNET_PROTOCOL)/message.o $(DDNET_PROTOCOL)/chunk.o $(DDNET_PROTOCOL)/packer.o \
$(DDNET_PROTOCOL)/snapshot.o $(DDNET_PROTOCOL)/int_string.o
ccflags-y += -DCODE_SPACE=KERNEL_SPACE -I$(src)/ddnet_protocol/include
CFLAGS_ddnet_protocol/src/message.o += $(CC_FLAGS_FPU)
CFLAGS_REMOVE_ddnet_protocol/src/message.o += $(CC_FLAGS_NO_FPU)

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
