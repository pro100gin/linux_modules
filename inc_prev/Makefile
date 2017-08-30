obj-m += kernel_inc_prev.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc show_shadow.c -o show_shadow
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -rf show_shadow 
