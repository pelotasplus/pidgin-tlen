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

#include "tlen.h"
#include "wb.h"

#include "account.h"
#include "accountopt.h"
#include "debug.h"
#include "notify.h"
#include "request.h"
#include "server.h"
#include "util.h"
#include "version.h"
#include "xmlnode.h"

struct tlen_wb {
	int brush_size;		/* their brush settings */
	int brush_color;

	int width;		/* whiteboard dimensions */
	int height;

	int my_brush_size;	/* our brush settings */
	int my_brush_color;
};

/* Tlen.pl doesn't have whiteboard support by default.

   We can send stuff in message packets though:

  <message from='sigsegv@tlen.pl'>
 	<wb>
 		<whiteboard commands>
 	</wb>
  </message>
*/

#if 0

/**
 * PurpleWhiteboard PRPL Operations
 */
struct _PurpleWhiteboardPrplOps
{
.       void (*start)(PurpleWhiteboard *wb);                                   /**< start function */
.       void (*end)(PurpleWhiteboard *wb);                                     /**< end function */
.       void (*get_dimensions)(PurpleWhiteboard *wb, int *width, int *height); /**< get_dimensions function */
.       void (*set_dimensions)(PurpleWhiteboard *wb, int width, int height);   /**< set_dimensions function */
.       void (*get_brush) (PurpleWhiteboard *wb, int *size, int *color);       /**< get the brush size and color */
.       void (*set_brush) (PurpleWhiteboard *wb, int size, int color);         /**< set the brush size and color */
.       void (*send_draw_list)(PurpleWhiteboard *wb, GList *draw_list);        /**< send_draw_list function */
.       void (*clear)(PurpleWhiteboard *wb);                                   /**< clear function */
};

#endif

void
tlen_wb_start(PurpleWhiteboard *wb)
{
	purple_debug_info("tlen_wb", "-> tlen_wb_start\n");

	purple_debug_info("tlen_wb", "<- tlen_wb_start\n");
}

void
tlen_wb_end(PurpleWhiteboard *wb)
{
	purple_debug_info("tlen_wb", "-> tlen_wb_end\n");

	g_free(wb->proto_data);

	purple_debug_info("tlen_wb", "<- tlen_wb_end\n");
}

void
tlen_wb_get_dimensions(const PurpleWhiteboard *wb, int *width, int *height)
{
	struct tlen_wb *twb = wb->proto_data;
	purple_debug_info("tlen_wb", "-> tlen_wb_get_dimensions\n");

	*width = twb->width;
	*height = twb->height;

	purple_debug_info("tlen_wb", "<- tlen_wb_get_dimensions\n");
}

void
tlen_wb_set_dimensions(PurpleWhiteboard *wb, int width, int height)
{
	purple_debug_info("tlen_wb", "-> tlen_wb_set_dimensions, w=%i, h=%i\n", width, height);
	purple_debug_info("tlen_wb", "<- tlen_wb_set_dimensions\n");
}

void
tlen_wb_get_brush(const PurpleWhiteboard *wb, int *size, int *color)
{
	struct tlen_wb *twb = wb->proto_data;

	purple_debug_info("tlen_wb", "-> tlen_wb_get_brush\n");

	*size = twb->my_brush_size;
	*color = twb->my_brush_color;

	purple_debug_info("tlen_wb", "<- tlen_wb_get_brush\n");
}

void
tlen_wb_set_brush(PurpleWhiteboard *wb, int size, int color)
{
	struct tlen_wb *twb = wb->proto_data;
	char buf[1024];
	PurpleConnection *gc = purple_account_get_connection(wb->account);
	TlenSession *s = gc->proto_data;

	purple_debug_info("tlen_wb", "-> tlen_wb_set_brush, size=%i, color=%i\n", size, color);

	twb->my_brush_size = size;
	twb->my_brush_color = color;

	purple_whiteboard_set_brush(wb, size, color);

	snprintf(buf, sizeof(buf), "<message to='%s'><wb><brush c='#%06x' s='%i'/></wb></message>",
		wb->who, twb->my_brush_color, twb->my_brush_size);

	tlen_send(s, buf);

	purple_debug_info("tlen_wb", "<- tlen_wb_set_brush\n");
}

void
tlen_wb_send_draw_list(PurpleWhiteboard *wb, GList *draw_list)
{
	GString *message;
	PurpleConnection *gc;
	TlenSession *s;

	purple_debug_info("tlen_wb", "-> tlen_wb_send_draw_list\n");

	g_return_if_fail(draw_list != NULL);

	message = g_string_new("<message");
        g_string_append_printf(message, " to='%s'><wb><data>", wb->who);

	for(; draw_list != NULL; draw_list = draw_list->next) {
		g_string_append_printf(message, "%d,", GPOINTER_TO_INT(draw_list->data));
	}

	g_string_append(message, "</data></wb></message>");

	purple_debug_info("tlen_wb", "DATA: %.*s", (int) message->len, message->str);
	purple_debug_info("tlen_wb", "<- tlen_wb_send_draw_list\n");

	gc = purple_account_get_connection(wb->account);
	s = gc->proto_data;

	tlen_send(s, message->str);

	g_string_free(message, TRUE);
}

/*
   <clear/>
*/
void
tlen_wb_clear(PurpleWhiteboard *wb)
{
	PurpleConnection *gc = purple_account_get_connection(wb->account);
	TlenSession *s = gc->proto_data;
	char buf[1024];

	purple_debug_info("tlen_wb", "-> tlen_wb_clear\n");

	snprintf(buf, sizeof(buf), "<message to='%s'><wb><clear/></wb></message>", wb->who);

	tlen_send(s, buf);

	purple_debug_info("tlen_wb", "<- tlen_wb_clear\n");
}

#define TLEN_WB_STATE_READY 1

void
tlen_wb_process_start(PurpleAccount *account, const char *from, xmlnode *tag)
{
	const char *w, *h;
	PurpleWhiteboard *wb;
	struct tlen_wb *twb;

	purple_debug_info("tlen_wb", "-> tlen_wb_process_start\n");

	wb = purple_whiteboard_create(account, from, TLEN_WB_STATE_READY);

	twb = g_new0(struct tlen_wb, 1);

	w = h = NULL;

	if (tag != NULL) {
		w = xmlnode_get_attrib(tag, "w");
		h = xmlnode_get_attrib(tag, "h");
	}

	twb->width = (w == NULL ? 640 : atoi(w));
	twb->height = (h == NULL ? 480 : atoi(h));

	twb->brush_size = 2;

	twb->my_brush_size = 2;

	wb->proto_data = twb;

	purple_whiteboard_start(wb);

	purple_debug_info("tlen_wb", "<- tlen_wb_process_start\n");
}

void
tlen_wb_process_data(PurpleWhiteboard *wb, xmlnode *data)
{
	int x, y;
	int dx, dy;
	char *d, *p;
	struct tlen_wb *twb;

	purple_debug_info("tlen_wb", "-> tlen_wb_process_data\n");

	if (wb == NULL) {
		purple_debug_info("tlen_wb", "received data but wb session not found!\n");
		return;
	}

	twb = wb->proto_data;

	d = (char *) xmlnode_get_data(data);
	if (d == NULL) {
		purple_debug_info("tlen_wb", "no data\n");
		return;
	}

	purple_debug_info("tlen_wb", "data to parse: %s\n", d);

	p = d;

	dx = strtol(p, &p, 10);
	if (*p == '\0') {
		purple_debug_info("tlen_wb", "invalid data\n");
		g_free(d);
		return;
	}

	p++;

	dy = strtol(p, &p, 10);
	if (*p == '\0') {
		purple_debug_info("tlen_wb", "done\n");
		g_free(d);
		return;
	}

	p++;

	purple_debug_info("tlen_wb", "%i,%i\n", dx, dy);

	x = dx;
	y = dy;

	while (1) {
		dx = strtol(p, &p, 10);
		if (*p == '\0') {
			purple_debug_info("tlen_wb", "invalid data\n");
			break;
		}

		p++;

		dy = strtol(p, &p, 10);

		purple_debug_info("tlen_wb", "%i,%i\n", dx, dy);

		purple_whiteboard_draw_line(wb, x, y, x + dx, y + dy, twb->brush_color, twb->brush_size);

		x += dx;
		y += dy;

		if (*p == '\0') {
			purple_debug_info("tlen_wb", "done\n");
			break;
		}

		p++;

	}

	g_free(d);
}

void
tlen_wb_process_brush(PurpleWhiteboard *wb, xmlnode *tag)
{
	const char *color, *size;
	struct tlen_wb *twb = wb->proto_data;

	color = xmlnode_get_attrib(tag, "c");
	size = xmlnode_get_attrib(tag, "s");

	twb->brush_color = color != NULL ? strtoul(color + 1, NULL, 16) : 0;
	twb->brush_size = size != NULL ? strtol(size, NULL, 10) : 1;

	/* Sane values */
	if (twb->brush_size < 0) {
		twb->brush_size = 1;
	} else if (twb->brush_size > 50) {
		twb->brush_size = 50;
	}
}

/**
  * Protocol:
  * 
  * Whiteboard commands are enclosed in message tags, as described on
  * top of the file
  *
  * Start a session with specified width, height, brush color
  *	<start w='1024' h='768' b='#ffffff'/>
  *
  * Set brush color/size
  *	<brush c='#000000' s='4'/>
  *
  * Clear the whiteboard
  *	<clear/>
  *
  */
void
tlen_wb_process(TlenSession *s, xmlnode *xml, const char *from)
{
	xmlnode *tag;
	PurpleWhiteboard *wb;
	PurpleAccount *account;

	purple_debug_info("tlen", "-> tlen_wb_process, from=%s\n", from);

	account = purple_connection_get_account(s->gc);

	/* Do we have a session for this user already? */
	wb = purple_whiteboard_get_session(account, from);

	/* Start session request */
	tag = xmlnode_get_child(xml, "start");
	if (tag != NULL) {
		/* No, let's start one */
		if (wb == NULL) {
			tlen_wb_process_start(account, from, tag);
		}
	} else if ((tag = xmlnode_get_child(xml, "data")) != NULL) {
		tlen_wb_process_data(wb, tag);
	} else if ((tag = xmlnode_get_child(xml, "clear")) != NULL) {
		purple_whiteboard_clear(wb);
	} else if ((tag = xmlnode_get_child(xml, "brush")) != NULL) {
		tlen_wb_process_brush(wb, tag);
	}

	purple_debug_info("tlen", "<- tlen_wb_process");
}

void
tlen_wb_send_request(PurpleBlistNode *node, gpointer data)
{
	PurpleConnection *gc = data;
	TlenSession *s = gc->proto_data;
	PurpleBuddy *b = (PurpleBuddy *)node;
	char buf[1024];
	PurpleWhiteboard *wb;

	purple_debug(PURPLE_DEBUG_INFO, "tlen", "<- tlen_chat_start_conference\n");

	snprintf(buf, sizeof(buf), "<message to='%s'><wb><start/></wb></message>", b->name);

	tlen_send(s, buf);

	wb = purple_whiteboard_get_session(purple_connection_get_account(gc), b->name);
	/* session with this user already active */
	if (wb != NULL) {
		return;
	}

	/*XXX hack */
	tlen_wb_process_start(purple_connection_get_account(gc), b->name, NULL);
}

PurpleWhiteboardPrplOps tlen_wb_ops =
{
	tlen_wb_start,		/* create */
	tlen_wb_end,		/* destroy */
	tlen_wb_get_dimensions,	/* get dimensions */
	tlen_wb_set_dimensions,	/* set dimensions */
	tlen_wb_get_brush,	/* get brush */
	tlen_wb_set_brush,	/* set brush */
	tlen_wb_send_draw_list,	/* send_draw_list */
	tlen_wb_clear		/* clear */
};
