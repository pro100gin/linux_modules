obj-m += kernel_netlink.o 

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
		gcc user_netlink.c -o user_netlink

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
		rm -rf user_netlink
