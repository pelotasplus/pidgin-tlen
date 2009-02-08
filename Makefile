CC?=		gcc
LOCALBASE?=	/usr/local
DESTDIR?=

CFLAGS+=`PKG_CONFIG_PATH=${LOCALBASE}/lib/pkgconfig pkg-config pidgin --cflags` \
	-I${LOCALBASE}/include \
	-fPIC \
	-Wall
DATE=	`grep TLEN_VERSION tlen.h | awk '{print $$3}' | sed -e 's/"//g'`

.c.o:
	$(CC) -c $< $(CFLAGS)

OBJS=	tlen.o auth.o chat.o wb.o avatar.o

all: ${OBJS}
	$(CC) -shared -fPIC -o libtlen.so ${OBJS}

clean:
	rm -f ${OBJS} libtlen.so *.core

tags: *.c *.h
	rm -f tags
	ctags *

install:
	install -d -o root -g wheel ${DESTDIR}${LOCALBASE}/lib/purple-2/
	install -o root -g wheel libtlen.so ${DESTDIR}${LOCALBASE}/lib/purple-2/
	for i in 16 22 48; do \
		install -d -o root -g wheel ${DESTDIR}${LOCALBASE}/share/pixmaps/pidgin/protocols/$$i/; \
		install -o root -g wheel tlen_$$i.png \
			${DESTDIR}${LOCALBASE}/share/pixmaps/pidgin/protocols/$$i/tlen.png; \
	done

dist: clean
	rm -f pidgin-tlen-${DATE}.tar.gz
	rm -rf pidgin-tlen-${DATE}
	mkdir pidgin-tlen-${DATE}
	cp README* avatar.[ch] chat.[ch] wb.[ch] auth.c tlen.[ch] tlen_*.png Makefile* pidgin-tlen-${DATE}
	tar zcvf pidgin-tlen-${DATE}.tar.gz pidgin-tlen-${DATE}
	rm -rf pidgin-tlen-${DATE}

.PHONY: tags
