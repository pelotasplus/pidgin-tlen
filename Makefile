CC?=		gcc
LOCALBASE?=	/usr/local
DESTDIR?=

CFLAGS+=`PKG_CONFIG_PATH=${LOCALBASE}/lib/pkgconfig pkg-config pidgin --cflags` \
	-I${LOCALBASE}/include \
	-fPIC \
	-Wall -Werror
DATE=	`grep TLEN_VERSION tlen.h | awk '{print $$3}' | sed -e 's/"//g'`

.c.o:
	$(CC) -c $< $(CFLAGS)

OBJS=	tlen.o auth.o chat.o wb.o

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

emotes:
	@test -d "emote_set" || ( echo -e "\nError: Put your emote set in ./emote_set dir. Make sure emo.xml is in there.\n" && exit 1 )
	@test -f "emote_set/emo.xml" || ( echo -e "\nError: emote_set/emo.xml not found. ./emote_set must contain emo.xml + gif files\n"; exit 1 )
	( cd emote_set && python ../emo_to_theme.py && cd .. ) || exit 1
	install -d -o root -g root $(DESTDIR)$(LOCALBASE)/share/pixmaps/pidgin/smileys/Tlen.pl
	install -o root -g root -m 644 emote_set/* $(DESTDIR)$(LOCALBASE)/share/pixmaps/pidgin/smileys/Tlen.pl/

dist: clean
	rm -f pidgin-tlen-${DATE}.tar.gz
	rm -rf pidgin-tlen-${DATE}
	mkdir pidgin-tlen-${DATE}
	cp README* *.py chat.* wb.* auth.c tlen.* tlen_*.png Makefile* pidgin-tlen-${DATE}
	tar zcvf pidgin-tlen-${DATE}.tar.gz pidgin-tlen-${DATE}
	rm -rf pidgin-tlen-${DATE}

.PHONY: tags
