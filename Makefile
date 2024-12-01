obj-m := rootkit.o
KDIR := /home/offpath/Documents/ec2600/sem3/kernel/linux-6.10.11
ARCH := x86_64

#CROSS_COMPILE := x86_64-linux-gnu-

all:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KDIR) M=$(PWD) clean