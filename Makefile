EXTRA_CFLAGS=-I/pool/leo4-devel/actor/mod2/include
LINUX=/root/linux-3.3/ 

filelist = *.c include/* Makefile actor.stp
obj-m += bench.o commtest.o actor.o 

actor-y := amain.o aproc.o


all:
	make -C $(LINUX) M=$(PWD) modules
	make -C $(LINUX) M=$(PWD) modules_install

tarball:
	tar cvf actor.tar $(filelist)
	gzip actor.tar

clean:
	make -C $(LINUX) M=$(PWD) clean

