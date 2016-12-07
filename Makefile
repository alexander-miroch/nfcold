
ARCH:=x86_64
ifeq ($(ARCH),x86)
 CFLAGS:=-m32
endif


.PHONY: clean

snif: snif.o
	gcc $(CFLAGS) -O2 snif.c -o nfcheck -lpcap

snif.o: snif.c 

clean: 
	rm -f  *.o nfcheck nfcold

nfcold:
	gcc $(CFLAGS) -O2 srv.c -o nfcold


install: 
	install -m 755 nfcheck.init $(DESTDIR)/etc/init.d/nfcheck
	install -m 755 nfcheck $(DESTDIR)/usr/sbin
	install -m 644 nfcheck.conf $(DESTDIR)/etc/sysconfig/nfcheck

nfcold_install:
	install -m 755 nfcold.init $(DESTDIR)/etc/init.d/nfcold
	install -m 755 nfcold $(DESTDIR)/usr/sbin
