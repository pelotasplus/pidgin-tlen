/*
 * Copyright (c) 2005 Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>
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

#include "tlen.h"
#include "chat.h"
#include "wb.h"

static PurplePlugin *my_protocol = NULL;

char *tlen_gender_list[] = {
	"Male or female",
	"Male",
	"Female",
};
const int tlen_gender_list_size = sizeof(tlen_gender_list) / sizeof(tlen_gender_list[0]);

TlenUserInfoElement tlen_user_template[] = {
	{"v",     "Show my details to others", TlenUIE_BOOL,   TlenUIE_RW, TlenUIE_DONTSHOW},
	{"first", "First name",                TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"last",  "Last name",                 TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"nick",  "Nickname",                  TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"email", "E-Mail address",            TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"c",     "City",                      TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"e",     "School",                    TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"s",     "Gender",                    TlenUIE_CHOICE, TlenUIE_RW, TlenUIE_SHOW},
	{"b",     "Birth year",                TlenUIE_STR,    TlenUIE_RW, TlenUIE_SHOW},
	{"j",     "Job",                       TlenUIE_INT,    TlenUIE_RO, TlenUIE_DONTSHOW},
	{"r",     "Looking for",               TlenUIE_INT,    TlenUIE_RO, TlenUIE_DONTSHOW},
	{"g",     "Voice",                     TlenUIE_INT,    TlenUIE_RO, TlenUIE_DONTSHOW},
	{"p",     "Plans",                     TlenUIE_INT,    TlenUIE_RO, TlenUIE_DONTSHOW}
};                                     

char *tlen_hash(const char *pass, const char *id);

/* Following two functions are from OpenBSD's ftp command.  Check:
 * http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ftp/fetch.c?rev=1.55&content-type=text/x-cvsweb-markup
 * for more information.
 *
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason Thorpe and Luke Mewburn.
 * [...]
 */
char
hextochar(const char *str)
{
	char c, ret;

	c = str[0];
	ret = c;
	if (isalpha(c))
		ret -= isupper(c) ? 'A' - 10 : 'a' - 10;
	else
		ret -= '0';
	ret *= 16;

	c = str[1];
	ret += c;
	if (isalpha(c))
		ret -= isupper(c) ? 'A' - 10 : 'a' - 10;
	else
		ret -= '0';
	return ret;
}

static char *
urldecode(const char *str)
{
	char *ret, c;
	int i, reallen;

	if (str == NULL) {
		return NULL;
	}
	if ((ret = malloc(strlen(str)+1)) == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "urldecode: cannot malloc memory\n");
		return NULL;
	}
	for (i = 0, reallen = 0; str[i] != '\0'; i++, reallen++, ret++) {
		c = str[i];
		if (c == '+') {
			*ret = ' ';
			continue;
		}
		/* Can't use strtol here because next char after %xx may be
		 * a digit. */
		if (c == '%' && isxdigit(str[i+1]) && isxdigit(str[i+2])) {
			*ret = hextochar(&str[i+1]);
			i+=2;
			continue;
		}
		*ret = c;
	}
	*ret = '\0';

	return ret-reallen;
}

/* Stolen from libtlen sources */
static char *
urlencode(const char *msg)
{
	unsigned char *s;
	unsigned char *str;
	unsigned char *pos;

	str = calloc(1, 3 * strlen(msg) + 1);
	if (str == NULL ) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "cannot allocate memory for encoded string\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- urlencode\n");

		return NULL;
	}

	s = (unsigned char *)msg;
	pos = str;

	while (*s != '\0') {
		if (*s == ' ') {
			*pos = '+';
			pos++;
		} else if ((*s < '0' && *s != '-' && *s != '.')
			|| (*s < 'A' && *s > '9')
			|| (*s > 'Z' && *s < 'a' && *s != '_')
			|| (*s > 'z')) {
			    sprintf((char *)pos, "%%%02X", *s);
			    pos += 3;
		} else {
			*pos = *s;
			pos++;
		}

		s++;
	}

	return (char *)str;
}

/* Converts msg from UTF to ISO */
static char *
fromutf(const char *msg)
{
	return g_convert(msg, strlen(msg), "ISO-8859-2", "UTF-8", NULL, NULL, NULL);
}

/* Converts msg from ISO to UTF */
static char *
toutf(const char *msg)
{
	return g_convert(msg, strlen(msg), "UTF-8", "ISO-8859-2", NULL, NULL, NULL);
}

char *
tlen_decode_and_convert(const char *str)
{
	char *decoded, *converted;

	if (str == NULL)
		return NULL;

	decoded = urldecode(str);
	if (decoded == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_decode_and_convert: unable to urldecode '%s'\n", str);
		return NULL;
	}

	converted = toutf(decoded);
	g_free(decoded);

	if (converted == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_decode_and_convert: unable to convert '%s'\n", decoded);
	}

	return converted;
}

char *
tlen_encode_and_convert(const char *str)
{
	char *encoded, *converted;

	if (str == NULL)
		return NULL;

	converted = fromutf(str);
	if (converted == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_encode_and_convert: unable to convert '%s'\n", str);
		return NULL;
	}

	encoded = urlencode(converted);
	g_free(converted);

	if (encoded == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_encode_and_convert: unable to urlencode '%s'\n", str);
	}

	return encoded;
}

static int
tlen_parse_subscription(const char *subscription)
{
	if (strcmp(subscription, "both") == 0) {
		return SUB_BOTH;
	} else if (strcmp(subscription, "none") == 0) {
		return SUB_NONE;
	} else if (strcmp(subscription, "to") == 0) {
		return SUB_TO;
	} else {
		return SUB_NONE;
	}
}

int
tlen_send(TlenSession *tlen, char *command)
{
	int ret;

	if (tlen == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "-- tlen_send: tlen is NULL!\n");
		return -1;
	}

	if (tlen->fd < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "-- tlen_send: tlen->fd < 0\n");
		return -1;
	}

	ret = write(tlen->fd, command, strlen(command));
	if (ret < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "-- tlen_send: write('%s') got %d, %s\n",
			command, errno, strerror(errno));
		purple_connection_error(purple_account_get_connection(tlen->account),
			_("Server has disconnected"));
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-- tlen_send: write('%s') got %d\n",
		command, ret);

	return ret;
}

static void
tlen_parser_element_start(GMarkupParseContext *context,
	const char *element_name, const char **attrib_names,
	const char **attrib_values, gpointer user_data, GError **error)
{
	//xmlnode     *node;
	int          i, ret;
	//const char  *attribval;
	TlenSession *tlen = (TlenSession *) user_data;
	char         buf[TLEN_BUFSIZE];//, type[100], id[100];
	char        *hash;
	xmlnode     *xml;

	if (!element_name)
		return;

#if 0
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_parser_element_start\n");

	/* Debugging */
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "element_name=\"%s\"\n", element_name);
	for (i = 0; attrib_names[i]; i++) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "attrib_names[%d]=\"%s\", attrib_values[%d]=%s\n",
			i, attrib_names[i], i, attrib_values[i]);
	}
#endif

	/* Session start; tag <s> is closed at the end of session */
	if ((strcmp(element_name, "s") == 0) && !tlen->xml) {
		// XXX what if `i' is not here?
		for (i = 0; attrib_names[i]; i++) {
			if (strcmp(attrib_names[i], "i") == 0) {
				purple_debug(PURPLE_DEBUG_INFO, "tlen", "attrib_values[%d]=\"%s\"\n", i, attrib_values[i]);
				strncpy(tlen->session_id, attrib_values[i], sizeof(tlen->session_id) - 1);
				purple_debug(PURPLE_DEBUG_INFO, "tlen", "got session id=%s\n", tlen->session_id);

				/* Got session id?  Now it's time to authorize ourselves */
				purple_connection_update_progress(tlen->gc, _("Authorizing"), 3, 4);

				hash = tlen_hash(tlen->password, tlen->session_id);
				purple_debug(PURPLE_DEBUG_INFO, "tlen", "hash=%s\n", hash);

				/* Free the password, zero it first */
				memset(tlen->password, 0, strlen(tlen->password));
				g_free(tlen->password);
				tlen->password = NULL;

				ret = snprintf(buf, sizeof(buf), TLEN_AUTH_QUERY,
					tlen->session_id, tlen->user, hash);
				free(hash);
				if (ret <= 0 || ret >= sizeof(buf)) {
					purple_debug(PURPLE_DEBUG_INFO, "tlen", "snprintf(): ret=%d\n", ret);
					return;
				}
				tlen_send(tlen, buf);
			}
		}
	} else {
		if (tlen->xml) {
			xml = xmlnode_new_child(tlen->xml, element_name);
		} else {
			xml = xmlnode_new(element_name);
		}

		for (i=0; attrib_names[i]; i++) {
			xmlnode_set_attrib(xml, attrib_names[i], attrib_values[i]);
		}

	       	tlen->xml = xml;
	}

	//purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_parser_element_start\n");
}

static char *
tlen_status2str(PurplePresence *presence) 
{
        if (purple_presence_is_status_active(presence, "away")) {
                return UC_AWAY_DESCR;
        } else if (purple_presence_is_status_active(presence, "available")) {
                return UC_AVAILABLE_DESCR;
        } else if (purple_presence_is_status_active(presence, "chat")) {
                return UC_CHAT_DESCR;
        } else if (purple_presence_is_status_active(presence, "dnd")) {
        	return UC_DND_DESCR;
        } else if (purple_presence_is_status_active(presence, "xa")) {
        	return UC_XA_DESCR;
        } else {
        	return UC_UNAVAILABLE_DESCR;
        }
}


static const char *
tlen_list_emblems(PurpleBuddy *b)
{
	TlenBuddy *tb = NULL;

	if (b->proto_data != NULL)
		tb = (TlenBuddy *) b->proto_data;
	
        if (!PURPLE_BUDDY_IS_ONLINE(b)) {
		if (tb && tb->subscription == SUB_NONE)
			return "not-authorized";
	}

	return NULL;
}

static void
tlen_set_buddy_status(PurpleAccount *account, PurpleBuddy *buddy, xmlnode *presence)
{
	xmlnode *node;
	char *show, *desc = NULL, *st;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_set_buddy_status: %s\n", buddy->name);

	show = (char *) xmlnode_get_attrib(presence, "type");
	if (!show) {
		node = xmlnode_get_child(presence, "show");
		if (!node) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "presence change without show\n");
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_set_buddy_status\n");
			return;
		}
		show = xmlnode_get_data(node);
	}

	/* User has set status */
	node = xmlnode_get_child(presence, "status");
	if (node) {
		desc = xmlnode_get_data(node);
		if (desc) {
			desc = tlen_decode_and_convert(desc);
		}
	}

	if (strcmp(show, UC_AVAILABLE_TEXT) == 0) {
		st = "available";
	} else if (strcmp(show, UC_AWAY_TEXT) == 0) {
		st = "away";
	} else if (strcmp(show, UC_CHAT_TEXT) == 0) {
		st = "chat";
	} else if (strcmp(show, UC_XA_TEXT) == 0) {
		st = "xa";
	} else if (strcmp(show, UC_DND_TEXT) == 0) {
		st = "dnd";
	} else {
                st = "offline";
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "unknown status: %s\n", show);
        }

	purple_debug_info("tlen", "st=%s\n", st);

	if (desc) {
		purple_prpl_got_user_status(account, buddy->name, st, "message", desc, NULL);
		g_free(desc);
	} else
		purple_prpl_got_user_status(account, buddy->name, st, NULL);

	purple_debug_info("tlen", "<- tlen_set_buddy_status: desc=%s\n", desc ? desc : "NULL");
}

void
tlen_request_auth(PurpleConnection *gc, char *name)
{
	char buf[256];
	TlenSession *tlen;

	tlen = gc->proto_data;

	snprintf(buf, sizeof(buf), TLEN_PRESENCE_SUBSCRIBE, name);
	tlen_send(tlen, buf);

}

static void
tlen_presence_authorize(TlenRequest *r)
{
	PurpleBuddy *b;
	char buf[200];
	TlenSession *tlen;
	TlenBuddy *tb;

	tlen = r->gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_presence_authorize: r->from='%s'\n", r->from);

	snprintf(buf, sizeof(buf), TLEN_PRESENCE_ACCEPT, r->from);
	tlen_send(tlen, buf);

	b = purple_find_buddy(r->gc->account, r->from);
	if (!b) {
		purple_account_request_add(r->gc->account, r->from, NULL, NULL, NULL);
	} else {
		tb = b->proto_data;
		if (tb && tb->subscription == SUB_NONE) {
			tlen_request_auth(r->gc, r->from);
		}
	}

	g_free(r->from);
	g_free(r);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_presence_authorize\n");
}

static void
tlen_presence_deny(TlenRequest *r)
{
	TlenSession *tlen;
	char buf[200];

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_presence_deny: r->from='%s'\n", r->from);

	tlen = r->gc->proto_data;

	/* First accept request and then ... */
	snprintf(buf, sizeof(buf), TLEN_PRESENCE_ACCEPT, r->from);
	tlen_send(tlen, buf);

	/* ... remove that buddy */
	snprintf(buf, sizeof(buf), TLEN_BUDDY_REMOVE, r->from);
	tlen_send(tlen, buf);

	g_free(r->from);
	g_free(r);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_presence_deny\n");
}

static int
tlen_process_presence(TlenSession *tlen, xmlnode *xml)
{
	const char *from, *type;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_process_presence\n");

	from = xmlnode_get_attrib(xml, "from");
	if (!from) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<presence> without from\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_presence\n");
		return 0;
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "from=%s\n", from);

	type = xmlnode_get_attrib(xml, "type");
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "type=%s\n", type ? type : "NONE");

	/* Subscribtion -- someone has agreed to add us to its buddy list */
	// <presence from='libtlendev@tlen.pl' type='subscribed'/>
	if (type && (strcmp(type, "subscribed") == 0)) {
		PurpleBuddy *b;
		TlenBuddy *tb;

		b = purple_find_buddy(tlen->gc->account, from);
		if (!b) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "unknown buddy %s\n", from);
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_presence\n");
			return 0;
		}

		tb = b->proto_data;
		if (tb) {
			tb->subscription = SUB_TO;
		}
	/* Someone wants to add you to his buddy list */
	} else if (type && (strcmp(type, "subscribe") == 0)) {
		char *msg;
		TlenRequest *r;

		r = g_new0(TlenRequest, 1);
		r->gc = tlen->gc;
		r->from = g_strdup(from);

		msg = g_strdup_printf(_("The user %s wants to add you to their buddy list."), from);
		
                purple_request_action(
			tlen->gc,
			NULL,
			msg,
			NULL,
			PURPLE_DEFAULT_ACTION_NONE,
			tlen->gc->account,
			from,
			NULL,
			r,
			2,
			_("Authorize"), G_CALLBACK(tlen_presence_authorize),
			_("Deny"), G_CALLBACK(tlen_presence_deny));

                g_free(msg);
	/* Status change */
	// <presence from='identyfikator@tlen.pl/t'><show>...</show><status>...</status></presence>
	} else {
		PurpleBuddy *buddy;
		int size;

		buddy = purple_find_buddy(tlen->gc->account, from);
		if (!buddy) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "unknown buddy %s\n", from);
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_presence\n");
			return 0;
		}

		purple_debug(PURPLE_DEBUG_INFO, "tlen", "xml=%s\n", xmlnode_to_formatted_str(xml, &size));

		tlen_set_buddy_status(tlen->gc->account, buddy, xml);
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_presence\n");

	return 0;
}

static int
tlen_process_message(TlenSession *tlen, xmlnode *xml)
{
	char *msg, *converted;
	const char *from, *stamp;
	xmlnode *body, *x, *wb;
	time_t sent = 0;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_process_message\n");

	from = xmlnode_get_attrib(xml, "from");
	if (!from) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "message without 'from'\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_message\n");
		return 0;
	}

	body = xmlnode_get_child(xml, "body");
	if (!body) {
		/* This could be a whiteboard message */
		wb = xmlnode_get_child(xml, "wb");
		if (wb == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "message without a 'body'\n");
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_message\n");
		} else {
			tlen_wb_process(tlen, wb, from);
		}

		return 0;
	}
	
	msg = xmlnode_get_data(body);
	if (!msg) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "message with empty 'body'\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_message\n");
		return 0;
	}

	converted = tlen_decode_and_convert(msg);
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "msg=%s\n", converted);
	msg = g_markup_escape_text(converted, -1);
	g_free(converted);

	/* timestamp of an offline msg  */
	x = xmlnode_get_child(xml, "x");
	if (x) {
		stamp = xmlnode_get_attrib(x, "stamp");
		if (stamp) {
			sent = purple_str_to_time(stamp, TRUE, NULL, NULL, NULL);
		}
	}

	serv_got_im(tlen->gc, from, msg, 0, sent == 0 ? time(NULL) : sent);


	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_message\n");

	return 0;
}

/* This can either be a typing notification or a chat message */
static int
tlen_process_notification(TlenSession *tlen, xmlnode *xml)
{
	const char *from, *type;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_process_notification\n");

	from = xmlnode_get_attrib(xml, "f");
	if (!from)
		return 0;

	/* Check if this is a chat message
       		<m f='261@c/~something' ...

	*/
	if (strstr(from, "@c") != NULL) {
		return tlen_chat_process_message(tlen, xml, from);
	}

	type = xmlnode_get_attrib(xml, "tp");
	if (!type)
		return 0;

	if (strcmp(type, "t") == 0) {
		 serv_got_typing(tlen->gc, from, 10, PURPLE_TYPING);
	}
		
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_notification\n");

	return 0;
}

static void
tlen_pubdir_user_info(TlenSession *tlen, const char *name, xmlnode *item)
{
	PurpleNotifyUserInfo *user_info;
	PurpleBuddy *buddy;
	int i;
	char *decoded;
	xmlnode *node;

	user_info = purple_notify_user_info_new();

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (tlen_user_template[i].display == TlenUIE_DONTSHOW)
			continue; 

		node = xmlnode_get_child(item, tlen_user_template[i].tag);

		if (!node) {
			purple_debug_info("tlen", "%s -> %s (!node)\n", tlen_user_template[i].tag, "");
			// row = g_list_append(row, g_strdup(""));
			continue;
		}

		decoded = NULL;
		if (tlen_user_template[i].format == TlenUIE_STR) {
			decoded = tlen_decode_and_convert(xmlnode_get_data(node));
		}

		purple_debug_info("tlen", "%s -> %s\n", tlen_user_template[i].tag,
			decoded ? decoded : "NULL"); 

		if (strcmp(tlen_user_template[i].tag, "s") == 0) {
			int gender = atoi(xmlnode_get_data(node));
			if (gender < 0 || gender >= tlen_gender_list_size)
				gender = 0;

			purple_notify_user_info_add_pair(user_info, tlen_user_template[i].desc,
				g_strdup(_(tlen_gender_list[gender])));
		} else {
			purple_notify_user_info_add_pair(user_info, tlen_user_template[i].desc,
				decoded ? decoded : g_strdup(xmlnode_get_data(node)));
		}

		if (decoded)
			g_free(decoded);
	}

        buddy = purple_find_buddy(purple_connection_get_account(tlen->gc), name);
        if (NULL != buddy) {
                PurpleStatus *status;
                const char *msg;
                char *text;

                status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));
                msg = purple_status_get_attr_string(status, "message");

                if (msg != NULL) {
                        text = g_markup_escape_text(msg, -1);
                        purple_notify_user_info_add_pair(user_info, _("Message"), text);
                        g_free(text);
                }
	}

	purple_notify_userinfo(tlen->gc,  name, user_info, NULL, NULL);
	purple_notify_user_info_destroy(user_info);
}

static void
tlen_pubdir_search_info(TlenSession *tlen, xmlnode *item)
{
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	int i;
	GList *row;
	xmlnode *node;
	char *decoded;

	purple_debug_info("tlen", "-> tlen_pubdir_search_info\n");

	results = purple_notify_searchresults_new();
	if (!results) {
		purple_notify_error(tlen->gc, NULL,
			_("Unable to display public directory information."),
			NULL);
		return;
	}

        column = purple_notify_searchresults_column_new(_("Tlen ID"));
        purple_notify_searchresults_column_add(results, column);

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (tlen_user_template[i].display == TlenUIE_DONTSHOW)
			continue; 
		
		column = purple_notify_searchresults_column_new(_(tlen_user_template[i].desc));
		purple_notify_searchresults_column_add(results, column);
	}

	while (item) {
		row = NULL;
		row = g_list_append(row, g_strdup(xmlnode_get_attrib(item, "jid")));

		for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
			if (tlen_user_template[i].display == TlenUIE_DONTSHOW)
				continue; 

			node = xmlnode_get_child(item, tlen_user_template[i].tag);

			if (!node) {
				purple_debug_info("tlen", "%s -> %s (!node)\n", tlen_user_template[i].tag, "");
				row = g_list_append(row, g_strdup(""));
				continue;
			}
	
			decoded = NULL;
			if (tlen_user_template[i].format == TlenUIE_STR) {
				decoded = tlen_decode_and_convert(xmlnode_get_data(node));
			}

			purple_debug_info("tlen", "%s -> %s\n", tlen_user_template[i].tag,
				decoded ? decoded : "NULL"); 

			if (strcmp(tlen_user_template[i].tag, "s") == 0) {
				int gender = atoi(xmlnode_get_data(node));
				if (gender < 0 || gender >= tlen_gender_list_size)
					gender = 0;

				row = g_list_append(row, g_strdup(_(tlen_gender_list[gender])));
			} else {
				row = g_list_append(row, decoded ? decoded : g_strdup(xmlnode_get_data(node)));
			}
		}

		purple_notify_searchresults_row_add(results, row);

		item = xmlnode_get_next_twin(item);
	}

	purple_notify_searchresults(tlen->gc,
		_("Tlen.pl Public Directory"),
		_("Search results"), NULL, results,
		NULL, //(PurpleNotifyCloseCallback)ggp_sr_close_cb,
		purple_connection_get_account(tlen->gc));

#if 0
	if (item != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "item=%s\n", xmlnode_to_formatted_str(item, &size));
	}

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (!tlen_user_template[i].edit)
			continue; 

		intval = 0;
		nodeval = NULL;
		node = NULL;

		if (item != NULL) {
			node = xmlnode_get_child(item, tlen_user_template[i].tag);
			if (node) {
				nodeval = xmlnode_get_data(node);
				if (nodeval != NULL) {
					intval = atoi(nodeval);
					decoded = tlen_decode_and_convert(nodeval);
					purple_debug_info("tlen", "%s == %s (%d)\n", tlen_user_template[i].desc, nodeval, intval);
				}
			}
		}

		if (strcmp(tlen_user_template[i].tag, "v") == 0) {
			field = purple_request_field_bool_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), nodeval ? intval : 1);
		} else if (strcmp(tlen_user_template[i].tag, "s") == 0) {
			field = purple_request_field_choice_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), intval);
			purple_request_field_choice_add(field, _("Unknown"));
			purple_request_field_choice_add(field, _("Male"));
			purple_request_field_choice_add(field, _("Female"));
		} else if (strcmp(tlen_user_template[i].tag, "b") == 0) {
			field = purple_request_field_int_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), intval);
		} else {
			field = purple_request_field_string_new(tlen_user_template[i].tag,
					_(tlen_user_template[i].desc), node ? decoded : "", FALSE);
		}

		nodeval = NULL;
		g_free(decoded);
		decoded = NULL;

		purple_request_field_group_add_field(group, field);
	}

	purple_request_fields(tlen->gc, _("Edit Tlen.pl public directory information"),
			_("Edit Tlen.pl public directory information"),
			_("All items below are optional."),
			fields,
			_("Save"), G_CALLBACK(tlen_pubdir_set_user_info),
			_("Cancel"), NULL,
			tlen->gc);
#endif
}

static GString *
tlen_pubdir_process_fields(PurpleConnection *gc, PurpleRequestFields *fields, int mode)
{
	PurpleRequestField *field;
	const char *text = NULL;
	char buf[128], *encoded;
	int i, intval;
	GString *tubabuf;

	tubabuf = g_string_new("");

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (tlen_user_template[i].edit == TlenUIE_RO)
			continue;

                field = purple_request_fields_get_field(fields, tlen_user_template[i].tag);

		if (mode == TlenUIE_MODE_SEARCH && strcmp(tlen_user_template[i].tag, "v") == 0)
			continue;

		if (mode == TlenUIE_MODE_SEARCH && strcmp(tlen_user_template[i].tag, "s") == 0
		    && purple_request_field_choice_get_value(field) == 0)
			continue;

		switch (tlen_user_template[i].format) {
			case TlenUIE_STR:
				text  = purple_request_field_string_get_value(field);
				break;
			case TlenUIE_CHOICE:
				intval = purple_request_field_choice_get_value(field);
				goto handle_integer;
			case TlenUIE_INT:
				intval = purple_request_field_int_get_value(field);
				goto handle_integer;
			case TlenUIE_BOOL:
				intval = purple_request_field_bool_get_value(field);
handle_integer:
				snprintf(buf, sizeof(buf), "%d", intval);
				text = buf;
				break;
		}

		encoded = NULL;

		if (text) {
			encoded = tlen_encode_and_convert(text);
		}

		if (encoded && !(mode == TlenUIE_MODE_SEARCH && strlen(encoded) == 0)) {
			g_string_append_printf(tubabuf, "<%s>%s</%s>", tlen_user_template[i].tag,
					encoded, tlen_user_template[i].tag);
			g_free(encoded);
		}	

		purple_debug_info("tlen", "%s -> %s\n", tlen_user_template[i].tag, text ? text : "NULL");
	}

	return tubabuf;
}

static void
tlen_pubdir_set_user_info(PurpleConnection *gc, PurpleRequestFields *fields)
{       
	TlenSession *tlen = gc->proto_data;
	GString *tubabuf;
	char *q, buf[512];

	purple_debug_info("tlen", "-> tlen_pubdir_set_user_info\n");

	tubabuf = tlen_pubdir_process_fields(gc, fields, TlenUIE_MODE_EDIT);

	q = g_string_free(tubabuf, FALSE);
	snprintf(buf, sizeof(buf), "%s%s%s", TLEN_SET_PUBDIR_HEADER, q, TLEN_SET_PUBDIR_FOOTER);

	tlen_send(tlen, buf);

	g_free(q);
}

static void
tlen_pubdir_edit_user_info(TlenSession *tlen, xmlnode *item)
{
	xmlnode *node;
	char *nodeval, *decoded;
	int size, i, j, intval;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	if (item != NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "item=%s\n", xmlnode_to_formatted_str(item, &size));
	}

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (tlen_user_template[i].edit == TlenUIE_RO)
			continue; 

		intval = 0;
		nodeval = NULL;
		node = NULL;
		// XXX: does this fix the XXX below? decoded wasn't initialized!
		decoded = NULL;

		if (item != NULL) {
			node = xmlnode_get_child(item, tlen_user_template[i].tag);
			if (node) {
				nodeval = xmlnode_get_data(node);
				if (nodeval != NULL) {
					intval = atoi(nodeval);
					decoded = tlen_decode_and_convert(nodeval);
					purple_debug_info("tlen", "%s == %s (%d)\n", tlen_user_template[i].desc, nodeval, intval);
				}
			}
		}

		if (strcmp(tlen_user_template[i].tag, "v") == 0) {
			field = purple_request_field_bool_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), nodeval ? intval : 1);
		} else if (strcmp(tlen_user_template[i].tag, "s") == 0) {
			field = purple_request_field_choice_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), intval);
			for (j = 0; j < tlen_gender_list_size; j++) {
				purple_request_field_choice_add(field, _(tlen_gender_list[j]));
			}
#if 0
		} else if (strcmp(tlen_user_template[i].tag, "b") == 0) {
			field = purple_request_field_int_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), intval);
#endif
		} else {
			field = purple_request_field_string_new(tlen_user_template[i].tag,
					_(tlen_user_template[i].desc), node ? decoded : "", FALSE);
		}

		nodeval = NULL;
		// XXX: On win32 freeing decoded leads to segfault
		g_free(decoded);

		purple_request_field_group_add_field(group, field);
	}

	purple_request_fields(tlen->gc, _("Edit Tlen.pl public directory information"),
			_("Edit Tlen.pl public directory information"),
			_("All items below are optional."),
			fields,
			_("Save"), G_CALLBACK(tlen_pubdir_set_user_info),
			_("Cancel"), NULL,
			tlen->gc->account, NULL, NULL, tlen->gc);
}
		
static int
tlen_email_notification(TlenSession *tlen, xmlnode *xml)
{
	const char *from, *subject;
	char *from_decoded, *subject_decoded;
	PurpleAccount *account = purple_connection_get_account(tlen->gc);

	if (!purple_account_get_check_mail(account))
		return 0;

	from = xmlnode_get_attrib(xml, "f");
	if (!from)
		return 0;
	from_decoded = tlen_decode_and_convert(from);

	subject = xmlnode_get_attrib(xml, "s");
	if (!subject) {
		g_free(from_decoded);
		return 0;
	}
	subject_decoded = tlen_decode_and_convert(subject);

	purple_notify_email(tlen->gc, subject_decoded, from_decoded,
		purple_account_get_username(tlen->account),
        	"http://poczta.o2.pl/", NULL, NULL);

	g_free(from_decoded);
	g_free(subject_decoded);

	return 0;
}

static void
tlen_set_away(PurpleAccount *account, PurpleStatus *status)
{
        PurpleConnection *gc = purple_account_get_connection(account);
        TlenSession *tlen = gc->proto_data;
        const char *status_id = purple_status_get_id(status), *pattern;
	char *msg, *msg2 = NULL, buf[1024];

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_set_away\n");

        if (!purple_status_is_active(status)) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_set_away\n");
                return;
	}

	/* Special "invisible" presence */
	if (strcmp(status_id, UC_INVISIBLE_TEXT) == 0) {
		tlen_send(tlen, TLEN_PRESENCE_INVISIBLE);
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_set_away\n");
		return;
	}
 
        msg = (char *) purple_status_get_attr_string(status, "message");
	if (msg) {
		msg2 = fromutf(msg);
		if (msg2 == NULL) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_set_away: can't convert msg\n");
			msg2 = g_strdup(msg);
		}

		msg = purple_unescape_html(msg2);
		g_free(msg2);

		purple_debug(PURPLE_DEBUG_INFO, "tlen", "unescaped=%s\n", msg);

		msg2 = urlencode(msg);
		if (!msg2) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "cannot urlencode away message\n");
			msg2 = g_strdup(msg);
		}
		g_free(msg);
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "encoded=%s\n", msg2);
	}

	if (msg2 != NULL)
		pattern = TLEN_PRESENCE_STATE;
	else
		pattern = TLEN_PRESENCE;

	snprintf(buf, sizeof(buf), pattern, status_id, msg2);
	g_free(msg2);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "buf=%s\n", buf);

	tlen_send(tlen, buf);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_set_away\n");
}

static int
tlen_process_iq(TlenSession *tlen, xmlnode *xml)
{
	const char *type, *id, *from;

	type = xmlnode_get_attrib(xml, "type");
       	id = xmlnode_get_attrib(xml, "id");
	from = xmlnode_get_attrib(xml, "from");

	if (!type) {
		return 0;
	}

	/* Process nodes from the chat server. We either have from='c' or
	 * from='123@c' */
	if (from != NULL && (strcmp(from, "c") == 0 || strstr(from, "@c") != NULL)) {
		return tlen_chat_process_iq(tlen, xml, type);
	}

	/* Yeah, sometimes id is not given ... */
	if (!id) {
		if (strcmp(type, "set") == 0) {
			xmlnode *query, *item;
			PurpleBuddy *b;
			const char *subscription, *jid;
			TlenBuddy *tb;

			query = xmlnode_get_child(xml, "query");
			if (!query)
				return 0;

			item = xmlnode_get_child(query, "item");
			if (!item)
				return 0;
			
			subscription = xmlnode_get_attrib(item, "subscription");
			if (!subscription)
				return 0;

			jid = xmlnode_get_attrib(item, "jid");
			if (!jid)
				return 0;

			b = purple_find_buddy(tlen->gc->account, jid);
			if (b) {
				tb = b->proto_data;
				if (tb) {
					tb->subscription = tlen_parse_subscription(subscription);
				}
			}
		}		
	/* Session stuff (login, authentication, etc.) */
	} else if (strncmp(id, tlen->session_id, strlen(tlen->session_id)) == 0) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "session stuff\n");
		/* We are authorized */
		if (strcmp(type, "result") == 0) {
			purple_connection_set_state(tlen->gc, PURPLE_CONNECTED);
			/* Getting user list */
			tlen_send(tlen, TLEN_GETROSTER_QUERY);
		/* Wrong usename or password */
		} else if (strcmp(type, "error") == 0) {
			purple_connection_error(tlen->gc, _("Wrong password or username"));
		}
	/* Roster */
	} else if ((strncmp(id, "GetRoster", 9) == 0) && (strncmp(type, "result", 6) == 0)) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "roster stuff\n");
		xmlnode *query, *item;
		xmlnode *groupxml;
		PurpleGroup *g, *tlen_group;
		PurpleBuddy *b;
		TlenBuddy *tb;
		char *jid, *name, *subscription, *group;


		query = xmlnode_get_child(xml, "query");
		if (!query) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "no query tag in GetRoster response\n");
			return 0;
		}

		/* Default group for Tlen.pl users.  If group "buddies" exists then use it.  Otherwise
		 * create our own "Tlen" group
		 */
		tlen_group = purple_find_group("Buddies");
		if (!tlen_group) {
			tlen_group = purple_find_group("Kontakty");
			if (!tlen_group) {
				tlen_group = purple_find_group("Tlen");
				if (!tlen_group) {
					tlen_group = purple_group_new("Tlen");
					purple_blist_add_group(tlen_group, NULL);
				}
			}
                }

		/* Parsing buddies */
		for (item = xmlnode_get_child(query, "item"); item; item = xmlnode_get_next_twin(item)) {
			jid = (char *) xmlnode_get_attrib(item, "jid");
			if (!jid)
				continue;

			subscription = (char *) xmlnode_get_attrib(item, "subscription");
			if (!subscription)
				continue;

			/* Buddy name */
			name = (char *) xmlnode_get_attrib(item, "name");
			if (name)
				name = tlen_decode_and_convert(name);
			else
				name = g_strdup(jid);
			
			/* Group that buddy belongs to */
			groupxml = xmlnode_get_child(item, "group");
			if (groupxml != NULL) {
				group = (char *) xmlnode_get_data(groupxml);
				group = tlen_decode_and_convert(group);
			} else {
				group = NULL;
			}

			/* If roster entry doesn't have group set or group is "Kontakty" (default group used by original Tlen.pl client)
			 * ten put that buddy into our default group (Buddies/Tlen) pointed by tlen_group */
			if (group == NULL || strcmp(group, "Kontakty") == 0) {
				g = tlen_group;
			} else {
				g = purple_find_group(group);
				if (g == NULL) {
					purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_process_iq: adding new group '%s'\n", group);
					g = purple_group_new(group);
					purple_blist_add_group(g, NULL);
				}
			}

			int add = 0;

			b = purple_find_buddy(tlen->gc->account, jid);
			if (b) {
				purple_debug_info("tlen", "already have buddy %s as %p (b->proto_data=%p)\n",
					jid, b, b->proto_data);
			} else {
				purple_debug_info("tlen", "adding new buddy %s\n", jid);

				b = purple_buddy_new(tlen->gc->account, jid, name);
				add = 1;
			}

			b->proto_data = g_new0(TlenBuddy, 1);
			tb = b->proto_data;
			tb->subscription = tlen_parse_subscription(subscription);

			if (add)
				purple_blist_add_buddy(b, NULL, g, NULL);

			purple_blist_alias_buddy(b, name);

			g_free(name);
		}

		tlen->roster_parsed = 1;

		/* Set our status, erm presence */
		tlen_set_away(tlen->gc->account, purple_presence_get_active_status(tlen->gc->account->presence));
	/* Pubdir info about myself */
	} else if ((strcmp(id, "tr") == 0) && (strcmp(type, "result") == 0)) {
		xmlnode *node, *item;

		node = xmlnode_get_child(xml, "query");
		if (!node)
			return 0;

		item = xmlnode_get_child(node, "item");

		tlen_pubdir_edit_user_info(tlen, item);
	/* Pubdir my details have been saved */
	} else if ((strcmp(id, "tw") == 0) && (strcmp(type, "result") == 0)) {
		purple_notify_info(tlen->gc->account, _("Public directory ..."),
			_("Public directory information saved successfully!"), NULL);
	} else if (from && strcmp(from, "tuba") == 0 && strcmp(type, "result") == 0) {
		xmlnode *node, *item;

		node = xmlnode_get_child(xml, "query");
		if (!node)
			return 0;

		item = xmlnode_get_child(node, "item");

		if (strcmp(id, "find_buddies") == 0) {
			tlen_pubdir_search_info(tlen, item);
		} else {
			tlen_pubdir_user_info(tlen, id, item);
		}
	}

	return 0;
}

/* return 0 if data was parsed; otherwise returns -1 */
static int
tlen_process_data(TlenSession *tlen, xmlnode *xml)
{
	int ret = 0;
	int size;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_process_data\n");
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "xml->name %s\n", xml->name);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "xml=\n%s\n", xmlnode_to_formatted_str(xml, &size));

	/* authorization, chat query responses */
	if (strncmp(xml->name, "iq", 2) == 0) {
		ret = tlen_process_iq(tlen, xml);
	} else if (strncmp(xml->name, "presence", 8) == 0) {
		ret = tlen_process_presence(tlen, xml);
	} else if (strncmp(xml->name, "message", 7) == 0) {
		ret = tlen_process_message(tlen, xml);
	} else if (strcmp(xml->name, "m") == 0) {
		ret = tlen_process_notification(tlen, xml);
	} else if (strcmp(xml->name, "n") == 0) {
		ret = tlen_email_notification(tlen, xml);
	} else if (strcmp(xml->name, "p") == 0) {
		ret = tlen_chat_process_p(tlen, xml);
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_process_data\n");

	return ret;
}

static void
tlen_parser_element_end(GMarkupParseContext *context,
	const gchar *element_name, gpointer user_data, GError **error)
{
	TlenSession *tlen = user_data;

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_parser_element_end\n");
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "element_name=\"%s\"\n", element_name);
 */

	if (tlen->xml == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "-- tlen_parser_element_end tlen->xml == NULL\n");
		return;
	}

	/* Is this a tag inside other tag? */
	if (tlen->xml->parent) {
                if(strcmp(tlen->xml->name, element_name) == 0)
                        tlen->xml = tlen->xml->parent;
        } else {
		tlen_process_data(tlen, tlen->xml);
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen->xml=%p\n", tlen->xml);
		xmlnode_free(tlen->xml);
		tlen->xml = NULL;
        }

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_parser_element_end\n");
 */
}

static void
tlen_parser_element_text(GMarkupParseContext *context, const char *text,
	gsize text_len, gpointer user_data, GError **error)
{
	TlenSession *tlen = user_data;

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_parser_element_text\n");
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "text_len=%d text=\"%s\"\n", text_len, text);
 */

	if (tlen->xml == NULL || text_len <= 0)
		return;

	xmlnode_insert_data(tlen->xml, text, text_len);

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_parser_element_text\n");
 */
}

static GMarkupParser parser = {
	tlen_parser_element_start,
	tlen_parser_element_end,
	tlen_parser_element_text,
	NULL,
	NULL
};

static GList *
tlen_status_types(PurpleAccount *account)
{
        PurpleStatusType *type;
        GList *types = NULL;

	// purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_status_types\n");

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "available",
                        _("Available"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);
                        
        type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "chat",
                        _("Chatty"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL); 
        types = g_list_append(types, type);
                        
        type = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "away",
                        _("Away"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type); 
                        
        type = purple_status_type_new_with_attrs(PURPLE_STATUS_EXTENDED_AWAY, "xa",
                        _("Extended Away"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "dnd",
                        _("Do Not Disturb"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_INVISIBLE, "invisible",
                        _("Invisible"), TRUE, TRUE, FALSE, "message", _("Message"),
			purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);

        type = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE, "offline",
                        _("Offline"), TRUE, TRUE, FALSE, "message", _("Message"),
                        purple_value_new(PURPLE_TYPE_STRING), NULL);
        types = g_list_append(types, type);
                        
	// purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_status_types\n");

	return types;
}

void
tlen_input_parse(PurpleConnection *gc, const char *buf, int len)
{
	TlenSession *tlen = gc->proto_data;

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_input_parse\n");
 */

	if (!g_markup_parse_context_parse(tlen->context, buf, len, NULL)) {
		g_markup_parse_context_free(tlen->context);
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "!g_markup_parse_context_parse\n");
		purple_connection_error(gc, _("XML Parse error"));
		return;
        }

/*
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_input_parse\n");
 */
}

void
tlen_input_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	TlenSession    *tlen = gc->proto_data;
	char            buf[TLEN_BUFSIZE];
	int             len;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_input_cb: fd=%d\n", tlen->fd);

	if (tlen->fd < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen->fd %d < 0", tlen->fd);
		return;
	}

	len = read(tlen->fd, buf, sizeof(buf) -1);
	if (len < 0) {
		purple_connection_error(gc, _("Read error"));
		return;
	} else if (len == 0) {
		purple_connection_error(gc, _("Server has disconnected"));
		return;
	}
	buf[len] = '\0';

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "got %d byte(s): '%s'\n", len, buf);

	tlen_input_parse(gc, buf, len);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_input_cb\n");
}

void
tlen_login_cb(gpointer data, gint source, const gchar *error_message)
{
	PurpleConnection *gc = data;
	TlenSession    *tlen = gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_login_cb\n");

	if (source < 0) {
		purple_connection_error(gc, _("Couldn't connect to host"));
		return;
	}
	
	fcntl(source, F_SETFL, 0);

	tlen->fd = source;

	purple_connection_update_progress(tlen->gc, _("Starting session"), 2, 4);

	tlen_send(tlen, TLEN_LOGIN_QUERY);

	tlen->gc->inpa = purple_input_add(tlen->fd, PURPLE_INPUT_READ, tlen_input_cb, tlen->gc);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_login_cb\n");
}


static void
tlen_keepalive(PurpleConnection *gc)
{
	TlenSession *tlen = gc->proto_data;

	tlen_send(tlen, TLEN_KEEPALIVE);
}

static void
tlen_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	TlenSession *tlen;
	PurpleProxyConnectData *err;
	char *domainname;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_login\n");

	gc = purple_account_get_connection(account);
	gc->proto_data = g_new0(TlenSession, 1);

	tlen = gc->proto_data;
	tlen->fd = -1;

	tlen->user = g_strdup(purple_account_get_username(account));
	if (!tlen->user) {
		purple_connection_error(gc, _("Invalid Tlen.pl ID"));
		return;
	}

	domainname = strstr(tlen->user, "@tlen.pl");
	if (domainname) {
		purple_connection_error(gc, _("Invalid Tlen.pl ID (please use just username without \"@tlen.pl\")"));
		return;
	}

	tlen->account = account;
	tlen->roster_parsed = 0;
	tlen->gc = gc;
	tlen->context = g_markup_parse_context_new(&parser, 0, tlen, NULL);
	tlen->password = g_strdup(purple_account_get_password(account));

	/* Create a hash table for chat lookups */
	// XXX: pass a free func! or is it not needed, since the tlen_chat_leave
	// event will be fired up in tlen_close
	tlen->chat_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	// XXX: a free func here too, l34kz!
	tlen->room_create_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	purple_connection_update_progress(gc, _("Connecting"), 1, 4);

	err = purple_proxy_connect(tlen->gc, account, SERVER_ADDRESS, SERVER_PORT, tlen_login_cb, gc);
	if (!err || !purple_account_get_connection(account)) {
		purple_connection_error(gc, _("Couldn't create socket"));
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_login\n");
		return;
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_login\n");
}


static void
tlen_close(PurpleConnection *gc)
{
	PurpleAccount *account;
	PurpleStatus *status;
	TlenSession *tlen = gc->proto_data;
	char *msg;
	char buf[512];

	if (tlen == NULL || tlen->fd < 0) {
		return;
	}

	account = purple_connection_get_account(gc);
	status = purple_account_get_active_status(account);
	msg = (char *) purple_status_get_attr_string(status, "message");

	if (!msg) {
		msg = g_strdup("Disconnected");
	} else {
		msg = tlen_encode_and_convert(msg);
	}	

	g_snprintf(buf, sizeof(buf), "<presence type='unavailable'><status>%s</status></presence>", msg);

	g_free(msg);

	tlen_send(tlen, buf);
	tlen_send(tlen, "</s>");

	if (gc->inpa)
		purple_input_remove(gc->inpa);

        close(tlen->fd);

        g_free(tlen->server);
        g_free(tlen->user);

	g_hash_table_destroy(tlen->chat_hash);
	g_hash_table_destroy(tlen->room_create_hash);

        g_free(tlen);
}

static int
tlen_send_im(PurpleConnection *gc, const char *who, const char *msg, PurpleMessageFlags flags)
{
	TlenSession      *tlen = gc->proto_data;
	char             buf[4096], *tmp;
	int              r;
	char            *converted, *unescaped;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_send_im\n");
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "who=\"%s\", msg=\"%s\", flags=0x%x\n", who, msg, flags);


	converted = fromutf(msg);
	if (converted == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "cannot convert msg\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_send_im\n");

		return 0;
	}

	unescaped = purple_unescape_html(converted);
	g_free(converted);

	tmp = urlencode(unescaped);
	if (!tmp) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "cannot urlencode msg\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_send_im\n");
		g_free(unescaped);

		return 0;
	}
	
	g_free(unescaped);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "tmp=%s\n", tmp);

	/* Check if we want to send a private chatroom message */
	if (strstr(who, "@c") != NULL) {
		tlen_chat_send_privmsg(tlen, who, tmp);
		g_free(tmp);

		return 1;
	} else {
		r = snprintf(buf, sizeof(buf), TLEN_MESSAGE, who, tmp);
	}
	
	g_free(tmp);

	if (r <= 0 || r > sizeof(buf)) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "snprintf() error\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_send_im\n");
		return 0;
	}

	r = tlen_send(tlen, buf);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_send_im\n");

	return 1;
}

static void
tlen_add_buddy(PurpleConnection *gc, PurpleBuddy *b, PurpleGroup *g)
{
	TlenSession *tlen;
	TlenBuddy *tb;
	char buf[250];

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_add_buddy\n");

	tlen = gc->proto_data;

	if (!tlen->roster_parsed) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "Roster hasn't been parsed yet.  Skipping add_buddy callback\n");
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_add_buddy\n");
		return;
	}

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "b=%p, b->proto_data=%p\n", b, b ? b->proto_data : NULL);

	if (!b->proto_data) {
		b->proto_data = g_new(TlenBuddy, 1);
		tb = b->proto_data;
		tb->subscription = SUB_NONE;
	}

	/* Adding to roster */
	if (g && g->name)
		snprintf(buf, sizeof(buf), TLEN_BUDDY_ADD, tlen->session_id, b->alias ? b->alias : b->name, b->name, g->name);
	else 
		snprintf(buf, sizeof(buf), TLEN_BUDDY_ADD_WOGRP, tlen->session_id, b->alias ? b->alias : b->name, b->name);
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "buf=%s\n", buf);	
	tlen_send(tlen, buf);

	/* Asking for subscribtion */
	snprintf(buf, sizeof(buf), TLEN_PRESENCE_SUBSCRIBE, b->name);
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "presence=%s\n", buf);	
	tlen_send(tlen, buf);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_add_buddy\n");
}

static void
tlen_remove_buddy(PurpleConnection *gc, PurpleBuddy *b, PurpleGroup *g)
{
	TlenSession *tlen;
	char buf[250];

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_remove_buddy\n");

	tlen = gc->proto_data;

	snprintf(buf, sizeof(buf), TLEN_PRESENCE_UNSUBSCRIBE, b->name);
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "buf=%s\n", buf);	

	tlen_send(tlen, buf);

	snprintf(buf, sizeof(buf), TLEN_BUDDY_REMOVE, b->name);
	purple_debug(PURPLE_DEBUG_INFO, "tlen", "buf=%s\n", buf);	

	tlen_send(tlen, buf);

	/* XXX Free b->data ? */

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_remove_buddy\n");
}

void
tlen_alias_buddy(PurpleConnection *gc, const char *who, const char *alias)
{
	int ret;
	char buf[4096];
	TlenSession *tlen;
	PurpleBuddy *buddy;
	PurpleGroup *group;
	char *encoded;

	tlen = gc->proto_data;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_alias_buddy: who=%s, alias=%s\n", who, alias);

	buddy = purple_find_buddy(tlen->gc->account, who);
	if (!buddy) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "cannot find budy %s\n", who);
		return;
	}

	group = purple_buddy_get_group(buddy);

	/* User wants to remove an alias */
	if (alias == NULL) {
		ret = snprintf(buf, sizeof(buf), TLEN_BUDDY_UNALIAS, who, group->name);
		if (ret < 0 || ret >= sizeof(buf)) {
			purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_alias_buddy: snprintf failed\n");
			return;
		}

		ret = tlen_send(tlen, buf);

		return;
	}

	encoded = tlen_encode_and_convert(alias);
	if (encoded == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_alias_buddy: can't encode alias\n");
		return;
	}

	ret = snprintf(buf, sizeof(buf), TLEN_BUDDY_SET, who, encoded, group->name);
	g_free(encoded);

	if (ret < 0 || ret >= sizeof(buf)) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_alias_buddy: snprintf failed\n");
		return;
	}

	tlen_send(tlen, buf);
}

static void
tlen_group_buddy(PurpleConnection *gc, const char *who, const char *old_group, const char *new_group)
{
	PurpleBuddy *buddy;
	TlenSession *tlen;
	char *group = NULL;
	char *alias = NULL;
	char buf[1024];
	int ret;

	tlen = gc->proto_data;

	buddy = purple_find_buddy(tlen->gc->account, who);

	purple_debug_info("tlen", "tlen_group_buddy: who=%s old_group=%s new_group=%s\n", who, old_group, new_group);

	group = tlen_encode_and_convert(new_group);
	if (group == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_group_buddy: can't encode group '%s'\n", new_group);
		return;
	}

	alias = tlen_encode_and_convert(buddy->alias);
	if (alias == NULL) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_group_buddy: can't encode alias '%s'\n", buddy->alias);
		goto end;
	}

	ret = snprintf(buf, sizeof(buf), TLEN_BUDDY_SET, who, alias, group);
	if (ret < 0 || ret >= sizeof(buf)) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_group_buddy: snprintf failed\n");
		goto end;
	}

	ret = tlen_send(tlen, buf);
	if (ret < 0) {
		purple_debug(PURPLE_DEBUG_INFO, "tlen", "tlen_group_buddy: tlen_send failed\n");
		goto end;
	}
end:
	g_free(group);
	g_free(alias);
}

static void
tlen_tooltip_text(PurpleBuddy *b, PurpleNotifyUserInfo *user_info, gboolean full)
{
	PurpleStatus *status;
	PurplePresence *presence;
	const char *tmp;
	char *tmp2;
	TlenBuddy *tb;

	if (full) {
		tb = (TlenBuddy *) b->proto_data;

		if (!tb) {
			tmp = _("Unknown");
		} else if (tb->subscription == SUB_BOTH) {
			tmp = _("Both");
		} else if (tb->subscription == SUB_NONE) {
			tmp = _("None");
		} else if (tb->subscription == SUB_TO) {
			tmp = _("To");
		} else  {
			tmp = _("Unknown");
		}

		purple_notify_user_info_add_pair(user_info, _("Subscription"), tmp);
	}

	presence = purple_buddy_get_presence(b);

	if (PURPLE_BUDDY_IS_ONLINE(b)) {
		purple_notify_user_info_add_pair(user_info, _("Status"), _(tlen_status2str(presence)));
	}

        status = purple_presence_get_active_status(presence);
	tmp = purple_status_get_attr_string(status, "message");
	if (tmp && strlen(tmp)) {
		tmp2 = g_markup_escape_text(tmp, -1);
		purple_notify_user_info_add_pair(user_info, _("Message"), tmp2);
		g_free(tmp2);
	}
}

static const char *
tlen_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return "tlen";
}

static void
tlen_buddy_rerequest_auth(PurpleBlistNode *node, gpointer data)
{
	PurpleBuddy *b;
	PurpleConnection *gc;

	if (!PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return;
	}

	b = (PurpleBuddy *) node;
	gc = purple_account_get_connection(b->account);

	/* Asking for subscribtion */
	tlen_request_auth(gc, b->name);
}

static GList *
tlen_blist_node_menu(PurpleBlistNode *node)
{
        PurpleConnection *gc;
	TlenBuddy *tb;
	PurpleBuddy *b;
	PurpleMenuAction *act;
	GList *m = NULL;

	if (PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		b = (PurpleBuddy *) node;
		tb = (TlenBuddy *) b->proto_data;
		gc = purple_account_get_connection(b->account);

		act = purple_menu_action_new(_("Start a conference"), PURPLE_CALLBACK(tlen_chat_start_conference), gc, NULL);
		m = g_list_append(m, act);
		
        	if (!tb || tb->subscription == SUB_NONE || tb->subscription == SUB_TO) {
                	act = purple_menu_action_new(_("(Re-)Request authorization"),
				PURPLE_CALLBACK(tlen_buddy_rerequest_auth),
				NULL, NULL);
			m = g_list_append(m, act);
		}

		act = purple_menu_action_new(_("Whiteboard"), PURPLE_CALLBACK(tlen_wb_send_request), gc, NULL);
		m = g_list_append(m, act);
	}

        return m;
}

static unsigned int
tlen_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState typing)
{
	TlenSession *tlen;
	char buf[100];

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "-> tlen_send_typing: who=%s typing=%d\n", who, typing);

	tlen = gc->proto_data;

	/* t - starts typing
	   u - stops typing
	 */
	snprintf(buf, sizeof(buf), TLEN_NOTIF_TYPING, who, typing == PURPLE_TYPING ? 't' : 'u');

	tlen_send(tlen, buf);

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_send_typing\n");

	return 0;
}

static void
tlen_pubdir_find_buddies_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	TlenSession *tlen = gc->proto_data;
	GString *tubabuf;
	char *q, buf[512], buf2[128];

	tubabuf = tlen_pubdir_process_fields(gc, fields, TlenUIE_MODE_SEARCH);

	q = g_string_free(tubabuf, FALSE);

	snprintf(buf2, sizeof(buf2), TLEN_SEARCH_PUBDIR_HEADER, "find_buddies");

	snprintf(buf, sizeof(buf), "%s%s%s", buf2, q, TLEN_SEARCH_PUBDIR_FOOTER);

	tlen_send(tlen, buf);

	g_free(q);
}

static void
tlen_pubdir_find_buddies(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	//TlenSession *tlen = gc->proto_data;
	int i, j;

	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	purple_debug_info("tlen", "tlen_pubdir_find_buddies\n");

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);

	for (i = 0; i < sizeof(tlen_user_template)/sizeof(tlen_user_template[0]); i++) {
		if (tlen_user_template[i].display == TlenUIE_DONTSHOW)
			continue; 
		
		if (strcmp(tlen_user_template[i].tag, "s") == 0) {
			field = purple_request_field_choice_new(tlen_user_template[i].tag, 
					_(tlen_user_template[i].desc), 0);
			for (j = 0; j < tlen_gender_list_size; j++) {
				purple_request_field_choice_add(field, _(tlen_gender_list[j]));
			}
		} else {
			field = purple_request_field_string_new(tlen_user_template[i].tag,
					_(tlen_user_template[i].desc), "", FALSE);
		}

		//field = purple_request_field_string_new(tlen_user_template[i].tag, _(tlen_user_template[i].desc), NULL, FALSE);
		purple_request_field_group_add_field(group, field);
	}

	purple_request_fields_add_group(fields, group);

	purple_request_fields(gc,
		_("Find buddies"),
		_("Find buddies"),
		_("Please, enter your search criteria below"),
		fields,
		_("OK"), G_CALLBACK(tlen_pubdir_find_buddies_cb),
		_("Cancel"), NULL,
		gc->account, NULL, NULL, gc);

	purple_debug_info("tlen", "tlen_pubdir_find_buddies\n");
}

static void
tlen_get_info(PurpleConnection *gc, const char *name)
{
	TlenSession *tlen = gc->proto_data;	
	char buf[256], header[256], *namecpy, *tmp;

	namecpy = strdup(name);
	tmp = strchr(namecpy, '@');
	if (tmp) {
		*tmp = '\0';
	}

	snprintf(header, sizeof(header), TLEN_SEARCH_PUBDIR_HEADER, name);

	snprintf(buf, sizeof(buf), "%s<i>%s</i>%s", header, namecpy, TLEN_SEARCH_PUBDIR_FOOTER);
	tlen_send(tlen, buf);

	free(namecpy);
}

static char *
tlen_status_text(PurpleBuddy *b)
{
        PurpleStatus *status;
	TlenBuddy *tb;
        const char *msg;
        char *text = NULL;
        char *tmp;

	tb = (TlenBuddy *) b->proto_data;

	if (!tb || tb->subscription == SUB_NONE) {
		text = g_strdup(_("Not Authorized"));
	} else {
		status = purple_presence_get_active_status(purple_buddy_get_presence(b));
		msg = purple_status_get_attr_string(status, "message");
		if (msg != NULL) {
			tmp = purple_markup_strip_html(msg);
			text = g_markup_escape_text(tmp, -1);
			g_free(tmp);
		} else if (!purple_status_is_available(status)) {
			tmp = g_strdup(purple_status_get_name(status));
			text = g_markup_escape_text(tmp, -1);
			g_free(tmp);
		}
	}

	purple_debug_info("tlen", "-- tlen_status_text: %s tb %p ret '%s'\n", b->name, tb, text ? text : "NULL");

	return text;
}

static void
tlen_pubdir_get_user_info(PurplePluginAction *action)
{       
        PurpleConnection *gc = (PurpleConnection *) action->context;
	TlenSession *tlen = gc->proto_data;

	tlen_send(tlen, TLEN_GET_PUBDIR_MYSELF);
}

static gboolean tlen_offline_message(const PurpleBuddy *buddy)
{
        return TRUE;
}

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_CHAT_TOPIC | OPT_PROTO_MAIL_CHECK | OPT_PROTO_UNIQUE_CHATNAME,
	NULL,			/* user_splits */
	NULL,			/* protocol_options */
	NO_BUDDY_ICONS,		/* icon_spec */
	tlen_list_icon,		/* list_icon */
	tlen_list_emblems,	/* list_emblems */
	tlen_status_text,	/* status_text */
	tlen_tooltip_text,	/* tooltip_text */
	tlen_status_types,	/* status_types */
	tlen_blist_node_menu,	/* blist_node_menu */
	tlen_chat_info,		/* chat_info */
	tlen_chat_info_defaults,/* chat_info_defaults */
	tlen_login,		/* login */
	tlen_close,		/* close */
	tlen_send_im,		/* send_im */
	NULL,			/* set_info */
	tlen_send_typing,	/* send_typing */
	tlen_get_info,		/* get_info */
	tlen_set_away,		/* set_away */
	NULL,			/* set_idle */
	NULL,			/* change_passwd */
	tlen_add_buddy,		/* add_buddy */
	NULL,			/* add_buddies */
	tlen_remove_buddy, 	/* remove_buddy */
	NULL,			/* remove_buddies */
	NULL,			/* add_permit */
	NULL,			/* add_deny */
	NULL,			/* rem_permit */
	NULL,			/* rem_deny */
	NULL,			/* set_permit_deny */
	tlen_join_chat,		/* join_chat */
	NULL,			/* reject_chat */
	NULL,			/* get_chat_name */
	tlen_chat_invite,	/* chat_invite */
	tlen_chat_leave,	/* chat_leave */
	tlen_chat_whisper,	/* chat_whisper */
	tlen_chat_send,		/* chat_send */
	tlen_keepalive,		/* keepalive */
	NULL,			/* register_user */
	NULL,			/* get_cb_info */
	NULL,			/* get_cb_away */
	tlen_alias_buddy,	/* alias_buddy */
	tlen_group_buddy,	/* group_buddy */
	NULL,			/* rename_group */
	NULL,			/* buddy_free */
	NULL,			/* convo_closed */
	NULL,			/* normalize */
	NULL,			/* set_buddy_icon */
	NULL,			/* remove_group */
	tlen_chat_get_cb_real_name, /* get_cb_real_name */
	tlen_chat_set_chat_topic,   /* set_chat_topic */
	NULL,			/* find_blist_chat */
	tlen_roomlist_get_list,	/* roomlist_get_list */
	tlen_roomlist_cancel,	/* roomlist_cancel */
	tlen_roomlist_expand_category, /* roomlist_expand_category */
	NULL,			/* can_receive_file */
	NULL,			/* send_file */
	NULL,			/* new xfer */
        tlen_offline_message,	/* offline_message */
        &tlen_wb_ops		/* whiteboard_prpl_ops */
};

static GList *
tlen_actions(PurplePlugin *plugin, gpointer context)
{
	GList *list = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Set user info..."), tlen_pubdir_get_user_info);
	list = g_list_append(list, act);

	act = purple_plugin_action_new(_("Find buddies..."), tlen_pubdir_find_buddies);
	list = g_list_append(list, act);

	return list;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                        /* type           */
	NULL,                                        /* ui_requirement */
	0,                                           /* flags          */
	NULL,                                        /* dependencies   */
	PURPLE_PRIORITY_DEFAULT,                       /* priority       */

	"prpl-tlen",                                 /* id             */
	"Tlen.pl",                                   /* name           */
	TLEN_VERSION,                                /* version        */

	N_("Tlen.pl Protocol Plugin"),               /* summary        */
	N_("The Tlen.pl Protocol Plugin"),           /* description    */
	"Aleksander Piotrowski <alek@mlodyinteligent.pl>",   /* author         */
	"http://nic.com.pl/~alek/pidgin-tlen",         /* homepage       */

	NULL,                                        /* load           */
	NULL,                                        /* unload         */
	NULL,                                        /* destroy        */

	NULL,                                        /* ui_info        */
	&prpl_info,                                  /* extra_info     */
	NULL,                                        /* prefs_info     */
	tlen_actions                                 /* actions        */
};

static void
init_plugin(PurplePlugin *plugin)
{
	my_protocol = plugin;
}

PURPLE_INIT_PLUGIN(tlen, init_plugin, info);
