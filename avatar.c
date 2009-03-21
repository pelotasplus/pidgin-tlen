/*
 * Copyright (c) 2009 Aleksander Piotrowski <aleksander.piotrowski@nic.com.pl>
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

#include "avatar.h"

#include <fcntl.h>

enum avatar_server_status {
	AS_NOT_CONNECTED,
	AS_CONNECTING,
	AS_CONNECTED
};

struct avatar {
	char        *login;
	char         type[2];
	char         md5[33];
};

struct avatar *current_av = NULL;
GList *queue = NULL;	/* list of avatars to get */
PurpleProxyConnectData *connect_data = NULL;
guint inpa = -1;
gint fd = -1;
char *rx_buf = NULL;
int rx_len = 0;
enum avatar_server_status serv_status = AS_NOT_CONNECTED;

static void tlen_avatar_connect(TlenSession *tlen);

static void
tlen_avatar_dump_queue(void)
{
	struct avatar *tmp_av;
	int i;

	purple_debug_info("tlen_avatar", "%d elems in queue\n", g_list_length(queue));
	
	if (g_list_length(queue) == 0) {
		return;
	}

	for (i = 0; i < g_list_length(queue); i++) {
		tmp_av = g_list_nth_data(queue, i);
		purple_debug_info("tlen_avatar", "%d => %s %s %s\n", i, tmp_av->login, tmp_av->type, tmp_av->md5);
	}
}

static void
tlen_avatar_process_queue(TlenSession *tlen)
{
	GList *first;

	tlen_avatar_dump_queue();

	first = g_list_first(queue);
	if (!first)
		return;

	current_av = first->data;

	purple_debug_info("tlen_avatar", "do pobrania %s %s %s\n", current_av->login, current_av->type, current_av->md5);

	char *login = g_strdup(current_av->login);
	if (!login)
		return;

	char *at = strchr(login, '@');
	if (!at) {
		g_free(login);
		return;
	}
	*at = '\0';

	// <avatar-get method='GET'>avatar/^login^/^type^?t=^token^</avatar-get>
	char get_buf[512];
	snprintf(get_buf, sizeof(get_buf),
"GET /avatar/%s/%s?t=%s HTTP/1.1\r\n"
"Host: mini10.tlen.pl\r\n\r\n",
	login, current_av->type, tlen->avatar_token);

	g_free(login);

	purple_debug_info("tlen_avatar", "get_buf='%s'", get_buf);

	ssize_t res = write(fd, get_buf, strlen(get_buf));
	purple_debug_info("tlen_avatar", "write(%zd): %d %s\n", res, errno, strerror(errno));
}

static void
tlen_avatar_disconnect(TlenSession *tlen)
{
	purple_debug_info("tlen_avatar", "disconnect\n");

	if (connect_data) {
		purple_proxy_connect_cancel(connect_data);
                connect_data = NULL;
	}

	if (inpa > 0) {
		purple_input_remove(inpa);
		inpa = 0;
	}

	if (fd >= 0) {
		close(fd);
		fd = -1;
	}

	g_free(rx_buf);
	rx_buf = NULL;
	rx_len = 0;
	
	serv_status = AS_NOT_CONNECTED;

	if (g_list_length(queue) > 0) {
		tlen_avatar_connect(tlen);
	}
}

static int
tlen_avatar_process_resp(TlenSession *tlen, char *buf, int len)
{
	purple_debug_info("tlen_avatar", "buf(%d)='%s'\n", len, buf);

#if 0
	int fp = open("/var/tmp/avatar", O_CREAT|O_WRONLY|O_TRUNC, 0600);
	if (fp) {
		write(fp, buf, len);
		close(fp);
	}
#endif

	if (strncmp(buf, "HTTP/1.0 200 OK", strlen("HTTP/1.0 200 OK")) != 0) {
		purple_debug_info("tlen_avatar", "not 200 OK resp\n");
		queue = g_list_remove(queue, current_av);
		return -1;
	}

	char *data = strstr(buf, "\r\n\r\n");
	if (!data) {
		purple_debug_info("tlen_avatar", "no end of header\n");
		return -1;
	}

	const char *cont_len_header = purple_strcasestr(buf, "Content-Length: ");
	if (!cont_len_header) {
		purple_debug_info("tlen_avatar", "no content-lenght header\n");
		return -1;
	}

	cont_len_header += strlen("Content-Length: ");
	
	char *end = strchr(cont_len_header, '\r');
	if (!end) {
		purple_debug_info("tlen_avatar", "no \\r after content-length header\n");
		return -1;
	}

	char *tmp = g_strndup(cont_len_header, end - cont_len_header);
	if (!tmp) {
		purple_debug_info("tlen_avatar", "g_strndup\n");
		return -1;
	}

	int cont_len = atoi(tmp);
	g_free(tmp);

	purple_debug_info("tlen_avatar", "cont_len='%d'\n", cont_len);

	data += 4;	/* skip \r\n\r\n */
	
	int datalen = buf + len - data;

	purple_debug_info("tlen_avatar", "datalen='%d'\n", datalen);

	if (!datalen || !cont_len || (datalen != cont_len)) {
		purple_debug_info("tlen_avatar", "datalen != cont_len; reading is not yet finished\n");
		return -1;
	}

	purple_buddy_icons_set_for_user(tlen->account, current_av->login, g_memdup(data, datalen), datalen, current_av->md5);

	queue = g_list_remove(queue, current_av);

	tlen_avatar_dump_queue();

	return 0;
}

static void
tlen_avatar_read_cb(gpointer data, gint source, PurpleInputCondition cond)
{
        char buf[512];
        gssize len;
	TlenSession *tlen = data;

        len = read(source, buf, sizeof(buf) - 1);
        if (len < 0 && errno == EAGAIN)
                return;
	if (len <= 0) {
                purple_debug_error("tlen_avatar", "read(%zd): %d %s\n", len, errno, g_strerror(errno));
		tlen_avatar_disconnect(tlen);
                return;
        }

        buf[len] = '\0';

	purple_debug_info("tlen_avatar", "got: '%s'\n", buf);

	rx_buf = g_realloc(rx_buf, len + rx_len + 1);
	memcpy(rx_buf + rx_len, buf, len + 1);
	rx_len += len;

	tlen_avatar_process_resp(tlen, rx_buf, rx_len);
}

static void
tlen_avatar_connect_cb(gpointer data, gint source, const gchar *error_message)
{
	TlenSession *tlen = data;

	connect_data = NULL;

	if (source < 0) {
		purple_debug_error("tlen_avatar", "avatar connect %s\n", error_message ? error_message : "NULL");
		serv_status = AS_NOT_CONNECTED;
		return;
	}

	fd = source;

	purple_debug_error("tlen_avatar", "fd ustawione na %d\n", fd);

	serv_status = AS_CONNECTED;

	inpa = purple_input_add(source, PURPLE_INPUT_READ, tlen_avatar_read_cb, tlen);

	tlen_avatar_process_queue(tlen);
}

static void
tlen_avatar_connect(TlenSession *tlen)
{
	if (serv_status != AS_NOT_CONNECTED) {
		purple_debug_info("tlen_avatar", "serv_status != AS_NOT_CONNECTED\n");
		return;
	}

	serv_status = AS_CONNECTING;

	connect_data = purple_proxy_connect(
		NULL, tlen->account, "mini10.tlen.pl", 80, tlen_avatar_connect_cb, tlen);
}

int
tlen_avatar_process(TlenSession *tlen, xmlnode *xml)
{
	xmlnode *token;
	char *msg;

	token = xmlnode_get_child(xml, "token");
	if (!token)
		return 0;

	msg = xmlnode_get_data(token);
	if (!msg)
		return 0;

	if (tlen->avatar_token)
		g_free(tlen->avatar_token);

	tlen->avatar_token = msg;

	return 0;
}

void
tlen_avatar_close(TlenSession *tlen)
{
	int i;
	struct avatar *av;

	g_free(tlen->avatar_token);

	for (i = 0; i < g_list_length(queue); i++) {
		av = g_list_nth_data(queue, i);
		free(av->login);
		free(av);
	}

	g_list_free(queue);
	
	tlen_avatar_disconnect(tlen);
}

void
tlen_avatar_get(TlenSession *tlen, PurpleBuddy *buddy, const char *md5, const char *type)
{
	const char *current_checksum = purple_buddy_icons_get_checksum_for_user(buddy);

	/* remove avatar if there is no md5/type in presence */
	if (!md5 || !type) {
		purple_debug_info("tlen_avatar", "removing avatar for user %s\n", buddy->name);
		purple_buddy_icons_set_for_user(tlen->account, buddy->name, NULL, 0, NULL);
		return;
	}

	if (current_checksum && strcmp(current_checksum, md5) == 0) {
		purple_debug_info("tlen_avatar", "already have current buddy icon; skipping\n");
		return;
	}

	struct avatar *av = g_new0(struct avatar, 1);
	if (!av)
		return;

	strncpy(av->type, type, sizeof(av->type) - 1);
	strncpy(av->md5, md5, sizeof(av->md5) - 1);
	av->login = g_strdup(buddy->name);
	if (!av->login) {
		g_free(av);
		return;
	}

	queue = g_list_append(queue, av);

	purple_debug_info("tlen_avatar", "added %s w/ md5 %s to queue\n", av->login, av->md5);
	
	tlen_avatar_connect(tlen);
}
