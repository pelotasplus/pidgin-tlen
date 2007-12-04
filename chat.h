/*
 * Copyright (c) 2006 Krzysztof Godlewski <sigsegv@tlen.pl>
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

#ifndef TLEN_CHAT_H
#define TLEN_CHAT_H

#include "tlen.h"
	
GList *tlen_chat_info(PurpleConnection *gc);
GHashTable *tlen_chat_info_defaults(PurpleConnection *gc, const char *chat_name);
PurpleRoomlist *tlen_roomlist_get_list(PurpleConnection *gc);
void tlen_roomlist_cancel(PurpleRoomlist *list);
void tlen_roomlist_expand_category(PurpleRoomlist *list, PurpleRoomlistRoom *category);
void tlen_join_chat(PurpleConnection *gc, GHashTable *data);
int tlen_chat_send(PurpleConnection *gc, int id, const char *msg, PurpleMessageFlags flags);
void tlen_chat_leave(PurpleConnection *gc, int id);
void tlen_chat_whisper(PurpleConnection *gc, int id, const char *who, const char *msg);
char *tlen_chat_get_cb_real_name(PurpleConnection *gc, int id, const char *who);
void tlen_chat_invite(PurpleConnection *gc, int id, const char *msg, const char *name);

void tlen_chat_start_conference(PurpleBlistNode *node, gpointer data);

int tlen_chat_process_iq(TlenSession *tlen, xmlnode *xml, const char *type);
int tlen_chat_process_p(TlenSession *tlen, xmlnode *xml);
int tlen_chat_process_message(TlenSession *s, xmlnode *xml, const char *from);
void tlen_chat_send_privmsg(TlenSession *s, const char *who, char *msg);

#endif
