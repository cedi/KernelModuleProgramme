obj-m += Main.o


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mv Main.ko NfHooksFirewall.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
