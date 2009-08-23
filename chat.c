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

#include "chat.h"

#include "prpl.h"
#include "conversation.h"
#include "server.h"

#define TLEN_CHAT_GET_TOPLEVEL_GROUPS	"<iq to='c' type='1'/>"
#define TLEN_CHAT_EXPAND_GROUP		"<iq to='c' type='1' p='%s'/><iq to='c' type='2' p='%s'/>"
/* id@~nick */
#define TLEN_CHAT_JOIN_ROOM		"<p to='%s/%s'/>"
#define TLEN_CHAT_JOIN_ANONYMOUS_ROOM	"<p to='%s'/>"
#define TLEN_CHAT_SEND_ROOM_MESSAGE	"<m to='%s'><b n='1' s='10' f='0' c='000000'>%s</b></m>"
#define TLEN_CHAT_ROOM_LEAVE		"<p to='%s'><s>unavailable</s></p>"
#define TLEN_CHAT_PRIV_MESSAGE		"<m to='%s'><b>%s</b></m>"

#define TLEN_CHAT_ANONYMOUS_ROOM_CREATE		"<p to='c' tp='c' id='%s'/>"
#define TLEN_CHAT_ROOM_INVITE			"<m to='%s'><x><inv to='%s'><r/></inv></x></m>"
#define TLEN_CHAT_ROOM_INVITE_WITH_MSG		"<m to='%s'><x><inv to='%s'><r>%s</r></inv></x></m>"

#define GROUP_FLAG_CAN_CREATE_ROOMS	0x01
#define GROUP_FLAG_HAS_SUBGROUPS	0x02

#define ROOM_FLAG_O2_ROOM	0x40	/* rooms defined by the nice o2 people */

typedef struct {
	int id;		/* A unique id for Purple */

	char *nick;	/* My nickname in this chat */
	char *jid;	/* The room's id: 123@c */

	PurpleConversation *conv;
	//PurpleRoomlistRoom *room;
	//GHashTable *members;
	gboolean joined;	/* Used to distinguish between presence notifications when joining
				   the room/after we joined it, so we can omit join notifications in
				   the window */

	GHashTable *privs;	/* Private conversations in this room. We keep Purple */
} TlenChat;

#define AFFILIATION_USER	"0"
#define AFFILIATION_OWNER	"1"
#define AFFILIATION_ADMIN	"2"
#define AFFILIATION_KICKED	"4"
#define AFFILIATION_SUPERUSER	"5"

/* Need to clean up the code a bit */
static void tlen_chat_process_x(TlenSession *s, TlenChat *c, xmlnode *x, const char *roomid);
static TlenChat * join_chat(TlenSession *s, char *id, const char *nick);

static TlenChat *
find_chat_by_id(TlenSession *s, const char *id)
{
	return g_hash_table_lookup(s->chat_hash, id);
}

static PurpleRoomlistRoom *
find_room_by_id(TlenSession *s, const char *id)
{
	return g_hash_table_lookup(s->room_hash, id);
}

/*
   1b@c/~lala -> id=1b@c, nick=~lala

   modifies input!

   nick might be NULL.
 */
static void
unparse_jid(char *from, char **id, char **nick)
{
	char *p;

	*id = from;

	p = strchr(from, '/');
	/* from='123@c' */
	if (p == NULL) {
		*nick = NULL;
		return;
	}

	*p = 0;
	p++;

	*nick = p;
}

GList *
tlen_chat_info(PurpleConnection *gc)
{
	struct proto_chat_entry *pce = NULL;
	GList *m = NULL;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_info\n");

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("Room:");
	pce->identifier = "id";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("Nickname:");
	pce->identifier = "nickname";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

GHashTable *
tlen_chat_info_defaults(PurpleConnection *gc, const char *chat_name)
{
	GHashTable *def;
	//TlenSession *s = gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_info_defaults\n");

	def = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	return def;
}

PurpleRoomlist *
tlen_roomlist_get_list(PurpleConnection *gc)
{
	char buf[128];

	PurpleRoomlistField *f = NULL;
	GList *fields = NULL;
	TlenSession *s = gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_roomlist_get_list\n");

	if (s->roomlist != NULL) {
		purple_roomlist_unref(s->roomlist);
	}

	if (s->room_hash != NULL) {
		g_hash_table_destroy(s->room_hash);
	}

	/* Create hash table for room id => PurpleRoomlistRoom association */
	s->room_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	s->roomlist = purple_roomlist_new(purple_connection_get_account(s->gc));

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING, "", "id", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_INT, "", "flags", TRUE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_INT, _("Users:"), "users", FALSE);
	fields = g_list_append(fields, f);

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_BOOL, _("o2 room:"), "o2room", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(s->roomlist, fields);

	snprintf(buf, sizeof(buf), TLEN_CHAT_GET_TOPLEVEL_GROUPS);

	tlen_send(s, buf);

	return s->roomlist;
}

void
tlen_roomlist_cancel(PurpleRoomlist *list)
{
	PurpleConnection *gc;
	TlenSession *s;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_roomlist_cancel\n");

	gc = purple_account_get_connection(list->account);
	s = gc->proto_data;

	purple_roomlist_set_in_progress(list, FALSE);

	if (s->roomlist == list) {
		s->roomlist = NULL;
		purple_roomlist_unref(list);
	}

	g_hash_table_destroy(s->room_hash);
	s->room_hash = NULL;
}

/*
   Top-level group list:

   <iq from='c' type='1'>
   	<l>
		<i i='1' f='3' n='!+M%B3odzi'/>
		<i i='243' f='3' n='Gry'/>
			...
	</l>
   </iq>

   <i> tag attributes:
   	i: group id
	f: flags
	n: name

   When expanding a group we get:

   <iq from='c' type='1' p='243'>
   	<l>
		<i i='244' f='2' n='Komputerowe'/>
			...
	</l>
   </iq>

   p in <iq> is the parent group's id
*/
static int
tlen_chat_process_group_list(TlenSession *tlen, xmlnode *xml)
{
	xmlnode *i, *l;
	const char *id, *f, *n, *p;
	char *decoded;
	unsigned int flags;
	PurpleRoomlistRoom *room;
	PurpleRoomlistRoom *parent;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_process_group_list\n");

	l = xmlnode_get_child(xml, "l");
	if (l == NULL) {
		goto out;
	}

	p = xmlnode_get_attrib(xml, "p");
	if (p != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "got p=%s\n", p);

		parent = find_room_by_id(tlen, p);
		if (parent != NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "got parent, %p, %s\n", parent, parent->name);
		}

	} else {
		parent = NULL;
	}

	for (i = xmlnode_get_child(l, "i"); i != NULL; i = xmlnode_get_next_twin(i)) {
		id = xmlnode_get_attrib(i, "i");
		f = xmlnode_get_attrib(i, "f");
		n = xmlnode_get_attrib(i, "n");

		if (id == NULL || n == NULL || f == NULL) {
			continue;
		}

		decoded = tlen_decode_and_convert(n);
		if (decoded == NULL) {
			continue;
		}

		flags = atoi(f);

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "adding '%s', id=%s\n", decoded, id);

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_CATEGORY, decoded, parent);
		purple_roomlist_room_add_field(tlen->roomlist, room, id);
		/* flags */
		purple_roomlist_room_add_field(tlen->roomlist, room, GINT_TO_POINTER(flags));
		/* Use as user count and 'o2room' property */
		flags = 0;
		/* user count */
		purple_roomlist_room_add_field(tlen->roomlist, room, GINT_TO_POINTER(flags));
		flags = TRUE;
		/* o2 room */
		purple_roomlist_room_add_field(tlen->roomlist, room, GINT_TO_POINTER(flags));

		purple_roomlist_room_add(tlen->roomlist, room);

		/* Add to the hash as well */
		g_hash_table_insert(tlen->room_hash, g_strdup(id), room);

		free(decoded);
	}

out:
	purple_roomlist_set_in_progress(tlen->roomlist, FALSE);
	//purple_roomlist_unref(tlen->roomlist);
	//tlen->roomlist = NULL;

	return 0;
}

/*
   <iq from='c' type='2' p='243'>
      <l x='1'>
         <i i='243@c' n='Gry' c='0' x='87'/>
      </l>
   </iq>
 */
static int
tlen_chat_process_room_list(TlenSession *s, xmlnode *xml)
{
	xmlnode *i, *l;
	const char *id, *x, *n, *p, *c;
	char *decoded;
	unsigned int flags, count, o2room;
	PurpleRoomlistRoom *room;
	PurpleRoomlistRoom *parent;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_process_group_list\n");

	l = xmlnode_get_child(xml, "l");
	if (l == NULL) {
		goto out;
	}

	p = xmlnode_get_attrib(xml, "p");
	if (p == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "parent is NULL\n");
		goto out;
	}

	parent = find_room_by_id(s, p);
	if (parent == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "got parent, %p, %s\n", parent, parent->name);
		goto out;
	}

	for (i = xmlnode_get_child(l, "i"); i != NULL; i = xmlnode_get_next_twin(i)) {
		id = xmlnode_get_attrib(i, "i");
		x = xmlnode_get_attrib(i, "x");
		n = xmlnode_get_attrib(i, "n");
		c = xmlnode_get_attrib(i, "c");

		if (id == NULL || n == NULL || x == NULL || c == NULL) {
			continue;
		}

		decoded = tlen_decode_and_convert(n);
		if (decoded == NULL) {
			continue;
		}

		flags = atoi(x);

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "adding '%s', id=%s\n", decoded, id);

		room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM, decoded, parent);
		purple_roomlist_room_add_field(s->roomlist, room, id);
		/* room flags */
		purple_roomlist_room_add_field(s->roomlist, room, GINT_TO_POINTER(flags));
		/* user count */
		count = atoi(c);
		purple_roomlist_room_add_field(s->roomlist, room, GINT_TO_POINTER(count));
		/* o2 room */
		o2room = flags & ROOM_FLAG_O2_ROOM;
		purple_roomlist_room_add_field(s->roomlist, room, GINT_TO_POINTER(o2room));

		purple_roomlist_room_add(s->roomlist, room);

		/* Add to the hash as well */
		g_hash_table_replace(s->room_hash, g_strdup(id), room);

		free(decoded);
	}

out:
	purple_roomlist_set_in_progress(s->roomlist, FALSE);
	//purple_roomlist_unref(tlen->roomlist);
	//tlen->roomlist = NULL;

	return 0;
}

/*
	<iq from='1b@c' type='5' n='Samotne+serca' x='87' cn='!+M%B3odzi'/>
*/
static int
tlen_chat_process_room_entered(TlenSession *s, xmlnode *xml)
{
	const char *from, *n;
	char *decoded;
	TlenChat *c;

	from = xmlnode_get_attrib(xml, "from");
	n = xmlnode_get_attrib(xml, "n");
	if (from == NULL || n == NULL) {
		return 0;
	}

	c = find_chat_by_id(s, from);
	/* This can be a room we entered because of an accepted invitation */
	if (c == NULL) {
		//c = join_chat(s, g_strdup(from), NULL);
		/* XXX: just create the room? */
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_room_entered: no chat with id=%s\n", from);
		return 0;
	}

	/*
	   This is a dumb hack to set nice conference names, which
	   usually look like: 100104 or similar. They don't always match
	   the room id, unfortunately. */
	if (strncmp(n, "10", 2) == 0 && strlen(n) == 6) {
		purple_conversation_set_name(c->conv, _("Conference"));
	} else {
		decoded = tlen_decode_and_convert(n);
		if (decoded == NULL) {
			return 0;
		}

		purple_conversation_set_name(c->conv, decoded);
		g_free(decoded);
	}

	c->joined = TRUE;

	return 0;
}

/*
	<iq from='243@c' type='error' code='412' free='xyzzy1'/>
*/
static void
tlen_chat_process_error(TlenSession *s, xmlnode *xml)
{
	const char *code;
	const char *free;
	char *msg, *tmp = NULL;

	code = xmlnode_get_attrib(xml, "code");
	if (code == NULL) {
		return;
	}

	if (strcmp(code, "412") == 0 || strcmp(code, "409") == 0) {
		/* Get suggested nickname */
		free = xmlnode_get_attrib(xml, "free");
		if (free != NULL) {
			tmp = tlen_decode_and_convert(free);
			if (tmp == NULL) {
				return;
			}
		}

		/* XXX: we could close the window automagically by sending a
		 * serv_chat_left event? */
		msg = g_strdup_printf(
			_("The nickname you've chosen is %s.\nThe server suggested an alternate nickname: %s.\n\n"
			"Please close the chat window and try joining with a different nickname."),
			/* bleh */
			code[2] == '9' ? "already taken" : "registered by another user",
			tmp);

		g_free(tmp);

		if (msg == NULL) {
			return;
		}

		purple_notify_error(s->gc, _("Nickname error"), _("Nickname already taken"), msg);

		g_free(msg);
	} else if (strcmp(code, "503") == 0) {
		purple_notify_error(s->gc, _("Server unavailable"), _("The Chat Server is currently unavailable"),
			_("Please try again in a moment."));
	}
}

int
tlen_chat_process_iq(TlenSession *tlen, xmlnode *xml, const char *type)
{
	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_process_iq, type=%s\n", type);

	/* We know that type is not NULL, tlen_process_iq checks for that
	 * condition */

	/* we don't always need the roomlist to be not NULL. Joining an
	 * anonymous room is one case */
	if (strcmp(type, "5") == 0) {
		tlen_chat_process_room_entered(tlen, xml);
		return 0;
	}

	if (tlen->roomlist == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "roomlist is NULL\n");
		return 0;
	}

	/* chat groups list */
	if (strcmp(type, "1") == 0) {
		return tlen_chat_process_group_list(tlen, xml);
	/* chat rooms list */
	} else if (strcmp(type, "2") == 0) {
		return tlen_chat_process_room_list(tlen, xml);
	/* chat room find results */
	} else if (strcmp(type, "3") == 0) {
	/* room entered */
	} else if (strcmp(type, "error") == 0) {
		tlen_chat_process_error(tlen, xml);
	}

	return 0;
}

/*
   <subject>bleh</subject>

   nick -> nick that set the subject, can be NULL

    XXX in fact, nick will always be null
 */
void
tlen_chat_process_subject(TlenChat *c, xmlnode *subject, char *nick)
{
	const char *data;
	char *decoded_data, *decoded_nick, *msg;

	decoded_nick = decoded_data = msg = NULL;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_subject, nick=%s\n", nick);

	if (nick != NULL) {
		decoded_nick = tlen_decode_and_convert(nick);
		if (decoded_nick == NULL) {
			return;
		}
	}

	data = xmlnode_get_data(subject);
	if (data != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_subject, got subject: %s\n", data);
		decoded_data = tlen_decode_and_convert(data);
		if (decoded_data != NULL) {
			purple_conv_chat_set_topic(PURPLE_CONV_CHAT(c->conv), nick, decoded_data);
			
			/* If there was no nickname given, we get this message
			 * because we joined a room. Dump the subject to the
			 * chat window */
			if (nick == NULL) {
				msg = g_markup_escape_text(decoded_data, -1);

				/* use as a temp pointer */
				g_free(decoded_nick);
				decoded_nick = purple_markup_linkify(msg);
				g_free(msg);

				msg = g_strdup_printf(_("Current room topic is: %s"), decoded_nick);

				purple_conv_chat_write(PURPLE_CONV_CHAT(c->conv), "", msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
			}
		}
	}

	g_free(decoded_data);
	g_free(decoded_nick);
	g_free(msg);
	g_free((char *) data);
}

/*
	<m f='261@c/~Pretorius'><b n='6' f='0' c='000000' s='10'>witaj+:D</b></m>

	n - font style (?)
	f - font family
	c - font color
	s - font size
	<b>msg body</b>

	if <m> contains tp='p', it's a private message
*/
int
tlen_chat_process_message(TlenSession *s, xmlnode *xml, const char *from)
{
	const char *msg = NULL, *stamp, *tp;
	xmlnode *body;
	char *id, *nick;
	char *decoded_msg, *decoded_nick, *escaped_msg;
	time_t msg_time;
	TlenChat *c;
	PurpleMessageFlags flags = 0;
	char nickbuf[128];

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_process_message\n");

	/* We can safely modify `from` here... */
	unparse_jid((char *)from, &id, &nick);

	c = find_chat_by_id(s, id);
	/* Chat not found, but this might still be an invitation */
	if (c == NULL) {
		body = xmlnode_get_child(xml, "x");
		if (body != NULL) {
			tlen_chat_process_x(s, NULL, body, id);
		}

		return 0;
	}

	tp = xmlnode_get_attrib(xml, "tp");

	escaped_msg = decoded_nick = decoded_msg = NULL;

	/* See if this is a subject change */
	body = xmlnode_get_child(xml, "subject");
	if (body != NULL) {
		tlen_chat_process_subject(c, body, nick);
		goto out;
	}

	/* message from a user */
	if (nick != NULL) {
		/* Check if this is a message we sent */
		/* use msg as a temp pointer */
		if (nick[0] == '~') {
			msg = nick + 1;
		} else {
			msg = nick;
		}

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "NICK: %s, my nick: %s\n", msg, c->nick);
		if (strcmp(msg, c->nick) == 0) {
			flags |= PURPLE_MESSAGE_SEND;
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "Message from self\n");
		} else {
			flags |= PURPLE_MESSAGE_RECV;
		}

		/* Decode the nick */
		decoded_nick = tlen_decode_and_convert(nick);
		if (decoded_nick == NULL) {
			goto out;
		}

		body = xmlnode_get_child(xml, "b");
		if (body == NULL) {
			goto out;
		}

		msg = xmlnode_get_data(body);
		if (msg == NULL) {
			goto out;
		}

		/* Check if the message contains our nick */
		if (strstr(msg, c->nick) != NULL) {
			flags |= PURPLE_MESSAGE_NICK;
		}

		decoded_msg = tlen_decode_and_convert(msg);
		if (decoded_msg == NULL) {
			goto out;
		}

		/* See if this is a message sent to us when joining a room */
		stamp = xmlnode_get_attrib(xml, "s");
		if (stamp != NULL) {
			msg_time = atol(stamp);
			flags |= PURPLE_MESSAGE_DELAYED;
		} else {
			time(&msg_time);
		}

		escaped_msg = g_markup_escape_text(decoded_msg, strlen(decoded_msg));

		/* XXX: Should probably use serv_got_im in both cases. This would
		 * require implementing 'normalize' I think. */

		/* Add the message to a window, or create a new private
		 * conversation */
		if (tp != NULL && strcmp(tp, "p") == 0) {
			snprintf(nickbuf, sizeof(nickbuf), "%s/%s", id, decoded_nick);

			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "Private message, nickbuf: '%s'\n", nickbuf);

			serv_got_im(s->gc, nickbuf, escaped_msg, PURPLE_MESSAGE_RECV, time(NULL));
		} else {
			//purple_conv_chat_write(PURPLE_CONV_CHAT(c->conv), decoded_nick, escaped_msg, flags, msg_time);
			/* Use the server subsystem, that's the proper way to do it */
			serv_got_chat_in(s->gc, c->id, decoded_nick, flags, escaped_msg, msg_time);
		}
	} else {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_message: NO NICK?\n");
	}

out:
	free(decoded_nick);
	free(decoded_msg);
	free(escaped_msg);
	free((char *) msg);

	return 0;
}

void
tlen_roomlist_expand_category(PurpleRoomlist *list, PurpleRoomlistRoom *category)
{
	PurpleConnection *gc;
	TlenSession *s;
	char buf[128];
	char *id;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_roomlist_expand_category\n");

	gc = purple_account_get_connection(list->account);
	s = gc->proto_data;

	id = g_list_nth_data(category->fields, 0);

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "expanding group id=%s\n", id);

	snprintf(buf, sizeof(buf), TLEN_CHAT_EXPAND_GROUP, id, id);

	tlen_send(s, buf);
}

static TlenChat *
join_chat(TlenSession *s, char *id, const char *nick)
{
	static int chat_id = 1;
	char buf[128];
	TlenChat *c;
	char *tmp;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_join_chat\n");

	/* Create a new chat struct */
	c = g_new0(TlenChat, 1);
	c->id = chat_id++;
	c->jid = id;

	/* If we don't get a nickname, it means we are already in
	   a chat and don't want to send stuff. Our username as a nickname
	   will do */
	if (nick != NULL) {
		tmp = tlen_encode_and_convert(nick);

		snprintf(buf, sizeof(buf), TLEN_CHAT_JOIN_ROOM, id, tmp);
		tlen_send(s, buf);
	} else {
		tmp = tlen_encode_and_convert(s->user);
	}

	/* keep the nickname encoded for quick comparison later */
	c->nick = tmp;
	/* XXX: use it */
	c->privs = g_hash_table_new(g_str_hash, g_str_equal);

	/* Create a chat window */
	c->conv = serv_got_joined_chat(s->gc, c->id, id);

	/* add the chat to our hash */
	g_hash_table_insert(s->chat_hash, strdup(id), c);

	return c;
}

struct join_chat_data {
	TlenSession *s;
	char *id;
};

static void
join_chat_ok_cb(struct join_chat_data *d, const char *nick)
{
	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "join_chat_ok_cb, nick=%s\n", nick);

	if (nick == NULL || strlen(nick) == 0) {
		free(d->id);
		free(d);
		
		return;
	}

	join_chat(d->s, d->id, nick);

	/* Don't free d->id, TlenChat will keep it */
	free(d);
}

static void
join_chat_cancel_cb(struct join_chat_data *d)
{
	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "join_chat_cancel_cb\n");

	g_free(d->id);
	g_free(d);
}

void
tlen_join_chat(PurpleConnection *gc, GHashTable *data)
{
	char *id;
	struct join_chat_data *d;
	TlenChat *c;

	TlenSession *s = gc->proto_data;

	id = g_hash_table_lookup(data, "id");

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "id=%s\n", id);

	/* If we are already in this room, ignore the request */
	c = find_chat_by_id(s, id);
	if (c != NULL) {
		return;
	}

	d = g_new(struct join_chat_data, 1);
	if (d == NULL) {
		return;
	}

	d->id = g_strdup(id);
	d->s = s;
	
	purple_request_input(gc, _("Enter your nickname"),
		_("Enter a nickname you wish to use"),
		_("You can leave the default to use a non-anonymous nickname.\nIf you do that, everyone will be able to see your TlenID"),
		s->user,
		FALSE, FALSE, NULL,
		_("Enter room"), PURPLE_CALLBACK(join_chat_ok_cb),
		_("Cancel"), PURPLE_CALLBACK(join_chat_cancel_cb),
		gc->account, NULL, NULL, d);
}

static PurpleConvChatBuddyFlags
tlen_chat_str_to_buddy_flags(const char *a)
{
	PurpleConvChatBuddyFlags flags = 0;

	if (a != NULL) {
		if (strcmp(a, AFFILIATION_ADMIN) == 0) {
			flags = PURPLE_CBFLAGS_HALFOP;
		} else if (strcmp(a, AFFILIATION_OWNER) == 0) {
			flags = PURPLE_CBFLAGS_OP;
		} else if (strcmp(a, AFFILIATION_SUPERUSER) == 0) {
			flags = PURPLE_CBFLAGS_FOUNDER;
		}
	}
	
	return flags;
}

struct invitation_data {
	TlenSession *s;
	char *roomid;
};

/*
   Join a room after an invitation was accepted
*/
static void
accept_invitation(struct invitation_data *d)
{
	char buf[512];

	snprintf(buf, sizeof(buf), TLEN_CHAT_JOIN_ANONYMOUS_ROOM, d->roomid);

	tlen_send(d->s, buf);

	g_free(d->roomid);
	g_free(d);
}

static void
reject_invitation(struct invitation_data *d)
{
	g_free(d->roomid);
	g_free(d);
}

/*
   aff change:
	<p f='261@c'><x><i i='~*muszka*' a='2'/></x></p>
   invitation:
	<m f='100064@c'><x><inv f='glentest' n='100064' x='8'><r/></inv></x></m>

   when we are kicked we get two tags:
   <p f='261@c'>
        <x>
	     <i i='~bziam+bziam+bziam' a='4'/>
	</x>
   </p>
   <p f='261@c/~bziam+bziam+bziam'>
       <s>unavailable</s>
       <kick r='zachowanie' e='1143370492'/>
   </p>

   xmlnode *x: the <x> tag
*/

static void
tlen_chat_process_x(TlenSession *s, TlenChat *c, xmlnode *x, const char *roomid)
{
	const char *nick, *a, *rdata = NULL;
	char *decoded, *tmp;
	xmlnode *i, *r;
	struct invitation_data *inv_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x\n");

	i = xmlnode_get_child(x, "i");
	/* It's an affiliation change */
	if (i != NULL) {
		if (c == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x: you called me with c=NULL!\n");
			return;
		}

		a = xmlnode_get_attrib(i, "a");
		nick = xmlnode_get_attrib(i, "i");

		if (nick == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x: nick is NULL\n");
			return;
		}

		decoded = tlen_decode_and_convert(nick);
		if (decoded == NULL) {
			return;
		}

		/* See if some looser was kicked. This could be us! */
		if (a != NULL && strcmp(a, AFFILIATION_KICKED) == 0) {
			if (nick[0] == '~') {
				nick = nick + 1;
			}

			/* We don't show notice about us being kicked. There is
			 * another tag (<p>) that will do that */
			if (strcmp(nick, c->nick) != 0) {
				tmp = g_strdup_printf(_("%s was kicked out of the room"), decoded);

				purple_conv_chat_write(PURPLE_CONV_CHAT(c->conv), "", tmp, PURPLE_MESSAGE_ERROR | PURPLE_MESSAGE_SYSTEM, time(NULL));
				g_free(tmp);

				/* Remove him from the list */
				purple_conv_chat_remove_user(PURPLE_CONV_CHAT(c->conv), decoded, NULL);
			}

			g_free(decoded);

			return;
		}

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x: changing %s\n", decoded);
		purple_conv_chat_user_set_flags(PURPLE_CONV_CHAT(c->conv), decoded, tlen_chat_str_to_buddy_flags(a));

		g_free(decoded);

		return;
	}

	/* Invitation? */
	i = xmlnode_get_child(x, "inv");
	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x: inv=%p\n", i);
	if (i != NULL) {
		if (roomid == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_x: you called me with roomid = NULL!\n");
			return;
		}
		
		/* See who is it from */
		a = xmlnode_get_attrib(i, "f");
		if (a == NULL) {
			return;
		}

		inv_data = g_new(struct invitation_data, 1);
		if (inv_data == NULL) {
			return;
		}

		inv_data->s = s;
		inv_data->roomid = g_strdup(roomid);

		if (inv_data->roomid == NULL) {
			g_free(inv_data);
			return;
		}

		/* XXX: if we get a 'n' tag, it's a chatroom invitation. We
		 * should ask for a nickname! */

		/* <m f='103358@c'><x><inv f='~gom+jabbar' n='Pod+palmami' x='30'><r/></inv></x></m> */

		/* See if there is a <r> tag in the <inv>. I'm not quite sure
		 * what it is, but we can send CDATA there, so I guess it's an
		 * optional invitation message */
		tmp = NULL;

		r = xmlnode_get_child(i, "r");
		if (r != NULL) {
			rdata = xmlnode_get_data(r);

			if (rdata != NULL) {
				tmp = tlen_decode_and_convert(rdata);
			}
		}

		if (tmp != NULL) {
			decoded = g_strdup_printf(_("%s has invited you to join a conference. He sent this message to encourage "
				"you to join:\n\n%s\n\nWould you like to join?"), a, tmp);
			g_free(tmp);
		} else {
			decoded = g_strdup_printf(_("%s has invited you to join a conference. Would you like to join?"), a);
		}

		/* XXX: add an option to ignore this user */
		/* This will probably need to handle room invitations too. The
		 * server will send a room name in this case, need to check this */
		purple_request_yes_no(s->gc,
			_("Conference invitation"), _("Conference invitation"), decoded, PURPLE_DEFAULT_ACTION_NONE,
			s->gc->account, NULL, NULL, inv_data, G_CALLBACK(accept_invitation), G_CALLBACK(reject_invitation));

		g_free(decoded);
		g_free((char *)rdata);
	}
}

/*
   Reacts on a message we get after we've requested a new room
   from the server.

	<p id='575551' f='100001@c' tp='c' a='3'/>
*/
static void
tlen_chat_process_room_creation_reply(TlenSession *s, const char *roomid, xmlnode *xml)
{
	const char *id;
	char *buddy = NULL;
	char buf[512];
	char *msg;
	char *roomname = NULL;	/* TODO: presumably the server will tell us the room name, if non-anonymous */
	/* TODO: use the 'a' attrib to set our flags */
	TlenChat *c;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_room_creation_reply, id=%s\n", roomid);

	/* Join the chat as any other */
	c = join_chat(s, g_strdup(roomid), s->user);
	/* We won't get an iq type=5, so we set this here */
	c->joined = TRUE;

	/* Get the request id */
	id = xmlnode_get_attrib(xml, "id");
	/* If we don't get the id, we're a few bytes of memory short - can't
	 * remove a room_create_hash key */
	if (id != NULL) {
		buddy = g_hash_table_lookup(s->room_create_hash, id);
		/* remove, in case the g_strdup we used when inserting
		 * the value failed */
		g_hash_table_remove(s->room_create_hash, id);
		/* If we've got the guy, send an invitation to him */
		if (buddy != NULL) {
			snprintf(buf, sizeof(buf), TLEN_CHAT_ROOM_INVITE, roomid, buddy);
			tlen_send(s, buf);

			/* Add a message that reminds the user about the
			 * invitation we just sent */
			msg = g_strdup_printf(_("An invitation to this conference was sent to %s"), buddy);
			if (msg != NULL) {
				purple_conv_chat_write(PURPLE_CONV_CHAT(c->conv), "", msg, PURPLE_MESSAGE_SYSTEM, time(NULL));
				g_free(msg);
			}

			g_free(buddy);
		}
	}

	if (roomname == NULL) {
		/* Set a nice name */
		purple_conversation_set_name(c->conv, _("Conference"));
	}

	/* Add ourselves to the list */
	purple_conv_chat_add_user(PURPLE_CONV_CHAT(c->conv), s->user, NULL, 0, FALSE);
}

/*
   User presence in chat:
   	<p f='1b@c/~miilusia' z='1' a='2'/>

   Or, when leaving the room:
   	<p f='1b@c/~nick'><s>unavailable</s><kick e='123142423'/></p>
 */
int
tlen_chat_process_p(TlenSession *tlen, xmlnode *xml)
{
	/* MESSY MESSY MESSY */
	const char *f, *z, *a, *l, *e, *tp, *r;
	PurpleConvChatBuddyFlags flags;
	char *nick, *id, *presence = NULL;
	char *decoded_nick;
	char *decoded_login;
	char *tmp, *decoded, *msg1, *msg2, *msg3;	/* message parts */
	TlenChat *c;
	xmlnode *s, *kick;
	/* for kick expiry time */
	time_t expiry;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_process_p\n");

	f = xmlnode_get_attrib(xml, "f");
	if (f == NULL) {
		return 0;
	}

	/* We can safely modify `from` here... */
	unparse_jid((char *)f, &id, &nick);

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "nick=%s, id=%s\n", nick, id);

	/* Find our chat struct */
	c = find_chat_by_id(tlen, id);
	if (c == NULL) {
		/* Since the chat was not found, we might be getting a reply for
		 * a room creation request. See if this is the case. */
		tp = xmlnode_get_attrib(xml, "tp");
		/* Yup, that's it */
		if (tp != NULL && strcmp(tp, "c") == 0) {
			tlen_chat_process_room_creation_reply(tlen, id, xml);
		} else {
			/* Just create the chat, we've joined it after an
			 * invitation */
			c = join_chat(tlen, g_strdup(id), NULL);
			/* Make all people that give join notifications */
			c->joined = TRUE;
		}
	}

	/* see whether this is a join or a leave */
	s = xmlnode_get_child(xml, "s");

	if (nick != NULL) {
		/* Decode the nickname */
		decoded_nick = tlen_decode_and_convert(nick);
		if (decoded_nick == NULL) {
			return 0;
		}
	} else {
		decoded_nick = NULL;
	}

	/* We might also get a login, when the user joins/leaves and we are
	 * admin in this room */
	decoded_login = NULL;

	l = xmlnode_get_attrib(xml, "l");
	if (l != NULL) {
		decoded_login = tlen_decode_and_convert(l);
	}

	/* a join */
	if (s == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "it's a join or an aff change\n");
		/* See if this is an affiliation change */
		s = xmlnode_get_child(xml, "x");
		if (s != NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "it's an aff change\n");
			tlen_chat_process_x(tlen, c, s, NULL);
			goto out;
		}

		if (decoded_nick == NULL) {
			goto out;
		}

		a = xmlnode_get_attrib(xml, "a");
		/* Set the flags accordingly */
		flags = tlen_chat_str_to_buddy_flags(a);

		/* XXX: The 'z' attrib tells us if the user is registered. We will use
		 * the 'typing' flag to show that to the user */
		z = xmlnode_get_attrib(xml, "z");
		if (z != NULL && strcmp(z, "1") == 0) {
			flags |= PURPLE_CBFLAGS_TYPING;
		}

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_p: '%s' joins %s\n", decoded_nick, id);

		/* Show the join notification only if we're already in the room when the
		   user joins */
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(c->conv), decoded_nick, decoded_login, flags, c->joined);
	/* a leave */
	} else {

		if (decoded_nick == NULL) {
			goto out;
		}

		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "tlen_chat_process_p: '%s' leaves %s\n", decoded_nick, id);
		presence = xmlnode_get_data(s);

		/* Process kick info */
		kick = xmlnode_get_child(xml, "kick");
		if (kick != NULL) {
			/* Get expire time and kick reason */
			e = xmlnode_get_attrib(kick, "e");
			r = xmlnode_get_attrib(kick, "r");

			if (r != NULL ) {
				decoded = tlen_decode_and_convert(r);
			} else {
				decoded = NULL;
			}

			/* See who was kicked. It could be us */
			/* XXX: make a function that does it */
			if (nick[0] == '~') {
				nick++;
			}

			if (strcmp(nick, c->nick) == 0) {
				msg1 = msg2 = msg3 = NULL;

				msg1 = g_strdup_printf(_("You have been kicked out of the room"));

				if (decoded != NULL) {
					msg2 = g_strdup_printf(_(", reason: %s"), decoded);
				}

				if (e != NULL) {
					expiry = atol(e);
					msg3 = g_strdup_printf(_(", you can join the room again on %s"), ctime(&expiry));
				}

				if (msg2) {
					/* Safe, if msg3 is NULL concat will stop */
					tmp = g_strconcat(msg1, msg2, msg3, NULL);
				} else {
					tmp = g_strconcat(msg1, msg3, NULL);
				}

				g_free(msg1);
				g_free(msg2);
				g_free(msg3);

				purple_conv_chat_write(PURPLE_CONV_CHAT(c->conv), "", tmp, PURPLE_MESSAGE_SYSTEM, time(NULL));
				g_free(tmp);

				serv_got_chat_left(tlen->gc, c->id);
				/* Clear the flag so that we don't send an
				 * unavailable presence when freeing stuff */
				c->joined = FALSE;
				/* Free mem */
				tlen_chat_leave(tlen->gc, c->id);

				goto out;
			}
		}

		if (presence != NULL && strcmp(presence, "unavailable") == 0) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "User %s is leaving room %s\n", decoded_nick, id);
			/* XXX: Bleh, use the login as a reason, so the user can
			 * see it */
			/* Remove the user only if he's still in the room */
			if (purple_conv_chat_find_user(PURPLE_CONV_CHAT(c->conv), decoded_nick)) {
				purple_conv_chat_remove_user(PURPLE_CONV_CHAT(c->conv), decoded_nick, decoded_login);
			}
		}
	}

out:
	g_free(decoded_nick);
	g_free(decoded_login);
	g_free(presence);

	return 0;
}

/*
   Find a chat by gaim id stuff
 */
struct find_by_id_data {
	int id;
	TlenChat *chat;
};

static void
find_by_purple_id_foreach_cb(gpointer key, gpointer value, gpointer user_data)
{
	TlenChat *chat = value;
	struct find_by_id_data *fbid = user_data;

	if (chat->id == fbid->id) {
		fbid->chat = chat;
	}
}

static TlenChat *
find_chat_by_purple_id(TlenSession *s, int id)
{
	TlenChat *chat;
	struct find_by_id_data *fbid = g_new0(struct find_by_id_data, 1);

	fbid->id = id;

	g_hash_table_foreach(s->chat_hash, find_by_purple_id_foreach_cb, fbid);
	chat = fbid->chat;
	g_free(fbid);

	return chat;
}

int
tlen_chat_send(PurpleConnection *gc, int id, const char *msg, PurpleMessageFlags flags)
{
	TlenSession *s = gc->proto_data;
	TlenChat *c;
	char buf[1024];
	char *encoded, *unescaped;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_send, id=%i, flags=0x%x\n", id, flags);

	c = find_chat_by_purple_id(s, id);
	if (c == NULL) {
		return 0;
	}

	if (strlen(msg) > 400) {
		return -1;
	}

	unescaped = purple_unescape_html(msg);
	if (unescaped == NULL) {
		return -1;
	}

	encoded = tlen_encode_and_convert(unescaped);
	if (encoded == NULL) {
		g_free(unescaped);
		return -1;
	}

	snprintf(buf, sizeof(buf), TLEN_CHAT_SEND_ROOM_MESSAGE, c->jid, encoded);
	tlen_send(s, buf);

	g_free(encoded);
	g_free(unescaped);

	return 0;
}

void
tlen_chat_whisper(PurpleConnection *gc, int id, const char *who, const char *msg)
{
	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_whisper, id=%i, who=%s\n", id, who);
}

void
tlen_chat_leave(PurpleConnection *gc, int id)
{
	TlenSession *s = gc->proto_data;
	TlenChat *c = find_chat_by_purple_id(s, id);
	char buf[1024];

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_leave, id=%i\n", id);

	/* Tell the chat server we are leaving */
	if (c->joined != FALSE) {
		snprintf(buf, sizeof(buf), TLEN_CHAT_ROOM_LEAVE, c->jid);
		tlen_send(s, buf);
	}

	g_hash_table_remove(s->chat_hash, c->jid);
	
	g_free(c->nick);
	g_free(c->jid);
	g_free(c);
}

/*
   Called on private conversation start
 */
char *
tlen_chat_get_cb_real_name(PurpleConnection *gc, int id, const char *who)
{
	TlenSession *s = gc->proto_data;
	TlenChat *c;
	char *n;

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "<- tlen_chat_get_cb_real_name, id=%i, who=%s\n", id, who);

	c = find_chat_by_purple_id(s, id);
	if (c == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "can't find chat\n");
		return NULL;
	}

	n = g_strdup_printf("%s/%s", c->jid, who);
	if (n == NULL) {
		return NULL;
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen_chat", "returning: '%s'\n", n);

	/* Now we need to put the private conversation into this room's privs
	 * hash, so we can react when the user (or we) leaves the room */
	// XXX: TODO

	return n;
}

/*
   sends a privmsg. The reason this function exists is that we need
   to encode the nickname only.

   msg is encoded and converted on input, so we only need to take
   care of `who`

   who = 123@c/~nick
*/
void
tlen_chat_send_privmsg(TlenSession *s, const char *who, char *msg)
{
	char buf[512];
	char *id, *nick;
	char *tmp;
	int put_tilde = 0;
	char *who_copy;

	who_copy = g_strdup(who);
	if (who_copy == NULL) {
		return;
	}

	unparse_jid(who_copy, &id, &nick);

	if (nick == NULL) {
		g_free(who_copy);

		return;
	}
	
	/* Skip the first char while decoding, since the server expects a raw
	   tilde */
	if (nick[0] == '~') {
		put_tilde = 1;
		nick++;
	}

	tmp = tlen_encode_and_convert(nick);
	nick = g_strdup_printf("%s/%s%s", id, put_tilde ? "~" : "", tmp);
	g_free(tmp);

	snprintf(buf, sizeof(buf), TLEN_CHAT_PRIV_MESSAGE, nick, msg);
	g_free(nick);

	tlen_send(s, buf);
	
	g_free(who_copy);
}

/* Set room/conference/chat topic */
void
tlen_chat_set_chat_topic(PurpleConnection *gc, int id, const char *topic)
{
	TlenSession *s = gc->proto_data;
	TlenChat *c;
	char *t;
	char buf[512];

	c = find_chat_by_purple_id(s, id);
	if (c == NULL) {
		return;
	}

	if (topic == NULL || topic[0] == '\0') {
		snprintf(buf, sizeof(buf), "<m to='%s'><subject></subject></m>", c->jid);
	} else {
		t = tlen_encode_and_convert(topic);
		snprintf(buf, sizeof(buf), "<m to='%s'><subject>%s</subject></m>", c->jid, t);
		g_free(t);
	}

	tlen_send(s, buf);
}


/* Sends a node that creates a room for us

   name - room name, or NULL if it's a conference room (anonymous room)
   buddy - tlenid of a buddy we want to automagically invite to the room
           once it is created
*/
static void
tlen_chat_room_create(TlenSession *s, const char *name, const char *buddy)
{
	static unsigned int request_id = 0x132457;
	char buf[512];
	char id[32];

	snprintf(id, sizeof(id), "%x", request_id++);

	/* Associate this id with the buddy. There is a slight chance the buddy
	 * might vanish while requesting the room (users with quick fingers!),
	 * so we strdup the name */
	if (buddy != NULL) {
		g_hash_table_insert(s->room_create_hash, g_strdup(id), g_strdup(buddy));
	}

	snprintf(buf, sizeof(buf), TLEN_CHAT_ANONYMOUS_ROOM_CREATE, id);

	tlen_send(s, buf);
}

/* Starts a conference with the right-clicked user */
void
tlen_chat_start_conference(PurpleBlistNode *node, gpointer data)
{
	PurpleConnection *gc = data;
	TlenSession *s = gc->proto_data;
	PurpleBuddy *b = (PurpleBuddy *)node;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_chat_start_conference\n");

	tlen_chat_room_create(s, NULL, b->name);
}

/* Send a room invitation to a buddy */
void
tlen_chat_invite(PurpleConnection *gc, int id, const char *msg, const char *name)
{
	TlenSession *s = gc->proto_data;
	TlenChat *c;
	char *n, *m;
	char buf[512];

	c = find_chat_by_purple_id(s, id);
	/* Shouldn't happen */
	if (c == NULL) {
		return;
	}
	
	m = NULL;
	n = tlen_encode_and_convert(name);

	if (n == NULL) { // || m == NULL) {
		goto out;
	}

	if (msg != NULL) {
		m = tlen_encode_and_convert(msg);
		snprintf(buf, sizeof(buf), TLEN_CHAT_ROOM_INVITE_WITH_MSG, c->jid, n, m);
	} else {
		snprintf(buf, sizeof(buf), TLEN_CHAT_ROOM_INVITE, c->jid, n);
	}

	tlen_send(s, buf);

out:
	g_free(n);
	g_free(m);
}
