/*
 * Copyright (c) 2005,2006 Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef TLEN_H
#define TLEN_H

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <glib.h>
#include <fcntl.h>

#define PURPLE_PLUGINS

/* from libpurple/internal.h */
#ifndef G_GNUC_NULL_TERMINATED
#  if __GNUC__ >= 4
#    define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#  else
#    define G_GNUC_NULL_TERMINATED
#  endif /* __GNUC__ >= 4 */
#endif /* G_GNUC_NULL_TERMINATED */

/* pidgin headers */
#include <version.h>
#include <xmlnode.h>
#include <account.h>
#include <debug.h>
#include <request.h>

#ifdef ENABLE_NLS
#  include <locale.h>
#  include <libintl.h>
#  define _(x) gettext(x)
#  ifdef gettext_noop
#    define N_(String) gettext_noop (String)
#  else
#    define N_(String) (String)
#  endif
#else
#  define N_(String) (String)
#  define _(x) ((char *)x)
#endif

#if 0
#ifndef G_GNUC_NULL_TERMINATED
#       if     __GNUC__ >= 4
#               define G_GNUC_NULL_TERMINATED __attribute__((__sentinel__))
#       else
#               define G_GNUC_NULL_TERMINATED
#       endif
#endif
#endif

#define TLEN_VERSION	"20071216"

#define SERVER_ADDRESS	"s1.tlen.pl"
#define SERVER_PORT	443

#define HUB_ADDRESS	"idi.tlen.pl"
#define HUB_PORT	80

#define TLEN_BUFSIZE         16000

#define TLEN_LOGIN_QUERY	"<s v='7'>"
#define TLEN_AUTH_QUERY		"<iq type='set' id='%s'><query xmlns='jabber:iq:auth'>" \
				"<username>%s</username><digest>%s</digest><resource>t</resource>" \
				"</query></iq>"
#define TLEN_GETROSTER_QUERY	"<iq type='get' id='GetRoster'><query xmlns='jabber:iq:roster'></query></iq>"
#define TLEN_KEEPALIVE		"  \t  "
#define TLEN_MESSAGE		"<message to='%s' type='chat'><body>%s</body></message>"
#define TLEN_PRESENCE_STATE	"<presence><show>%s</show><status>%s</status></presence>"
#define TLEN_PRESENCE		"<presence><show>%s</show></presence>"
#define TLEN_PRESENCE_INVISIBLE	"<presence type='invisible'></presence>"
#define TLEN_PRESENCE_SUBSCRIBE "<presence to='%s' type='subscribe'/>"
#define TLEN_PRESENCE_UNSUBSCRIBE "<presence to='%s' type='unsubscribe'/>"
#define TLEN_PRESENCE_ACCEPT    "<presence to='%s' type='subscribed'/>"
#define TLEN_NOTIF_TYPING	"<m to='%s' tp='%c'/>"
#define TLEN_BUDDY_REMOVE	"<iq type='set'><query xmlns='jabber:iq:roster'><item jid='%s' subscription='remove'></item></query></iq>"
/* XXX: tutaj potrzebne sa jeszcze tagi <group> */
#define TLEN_BUDDY_ADD		"<iq type='set' id='%s'><query xmlns='jabber:iq:roster'><item name='%s' jid='%s'><group>%s</group></item></query></iq>"
#define TLEN_BUDDY_ADD_WOGRP	"<iq type='set' id='%s'><query xmlns='jabber:iq:roster'><item name='%s' jid='%s'></item></query></iq>"
#define TLEN_BUDDY_SET		"<iq type='set'><query xmlns='jabber:iq:roster'><item jid='%s' name='%s'><group>%s</group></item></query></iq>"
#define TLEN_BUDDY_UNALIAS	"<iq type='set'><query xmlns='jabber:iq:roster'><item jid='%s'><group>%s</group></item></query></iq>"

#define TLEN_GET_PUBDIR_MYSELF	"<iq type='get' id='tr' to='tuba'><query xmlns='jabber:iq:register'></query></iq>"
#define TLEN_SET_PUBDIR_HEADER  "<iq type='set' id='tw' to='tuba'><query xmlns='jabber:iq:register'>"
#define TLEN_SET_PUBDIR_FOOTER  "</query></iq>"
#define TLEN_SEARCH_PUBDIR_HEADER  "<iq type='get' id='%s' to='tuba'><query xmlns='jabber:iq:search'>"
#define TLEN_SEARCH_PUBDIR_FOOTER  "</query></iq>"

#define UC_INVISIBLE_TEXT	"invisible"

#define UC_UNAVAILABLE_TEXT	"offline"
#define UC_UNAVAILABLE_DESCR	"Offline"

#define UC_AVAILABLE		2
#define UC_AVAILABLE_TEXT	"available"
#define UC_AVAILABLE_DESCR	"Available"

#define UC_AWAY			3
#define UC_AWAY_TEXT		"away"
#define UC_AWAY_DESCR		"Away"

#define UC_CHAT			4
#define UC_CHAT_TEXT		"chat"
#define UC_CHAT_DESCR		"Chatty"

#define UC_XA			5
#define UC_XA_TEXT		"xa"
#define UC_XA_DESCR		"Extended away"

#define UC_DND			6
#define UC_DND_TEXT		"dnd"
#define UC_DND_DESCR		"Do not disturb"

#define SUB_BOTH	1
#define SUB_NONE	2
#define SUB_TO		3

typedef struct {
	int   subscription;	/* Subscription status */
} TlenBuddy;

typedef struct {
	PurpleConnection      *gc;
	gint                 fd;

	char                 session_id[100];	/* Session ID used in many other places */
	GMarkupParseContext *context;		/* Parser context used to parse protocol traffic */
	xmlnode             *xml;		/* XML object created from data sent by server */
	int roster_parsed;			/* Was roster already parsed?  If not, then we ignore add_buddy calls */

	PurpleAccount         *account;
	char                *server;
	int                  port;
	char                *user;
	char                *password;

	/* Chat stuff */
	PurpleRoomlist        *roomlist;
	GHashTable          *room_hash;		/* Temporary hashtable for the roomlist */
	GHashTable          *chat_hash;		/* This is where we keep open chat rooms */
	GHashTable          *room_create_hash;	/* Room creation request id hash */
} TlenSession;

typedef struct {
	PurpleConnection *gc;
	char *from;
} TlenRequest;

typedef struct {
	char *tag;
	char *desc;
	int   format;
	int   edit;	/* Can user edit this value? */
	int   display;	/* Should this value be shown in pubdir search results? */
} TlenUserInfoElement;

#define TlenUIE_RO 0
#define TlenUIE_RW 1

#define TlenUIE_DONTSHOW 0
#define TlenUIE_SHOW 1

#define TlenUIE_INT 0
#define TlenUIE_STR 1
#define TlenUIE_BOOL 2
#define TlenUIE_CHOICE 3

#define TlenUIE_MODE_EDIT 0
#define TlenUIE_MODE_SEARCH 1

typedef struct TlenUserInfo_s TlenUserInfo;

int tlen_send(TlenSession *tlen, char *command);
char * tlen_decode_and_convert(const char *str);
char * tlen_encode_and_convert(const char *str);

#endif /* TLEN_H */
