/*
 * Copyright (c) 2014, Vsevolod Stakhov
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *	 * Redistributions of source code must retain the above copyright
 *	   notice, this list of conditions and the following disclaimer.
 *	 * Redistributions in binary form must reproduce the above copyright
 *	   notice, this list of conditions and the following disclaimer in the
 *	   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef RDNS_EV_H_
#define RDNS_EV_H_

#include <ev.h>
#include <stdlib.h>
#include <string.h>
#include "rdns.h"

static void* rdns_libev_add_read (void *priv_data, int fd, void *user_data);
static void rdns_libev_del_read(void *priv_data, void *ev_data);
static void* rdns_libev_add_write (void *priv_data, int fd, void *user_data);
static void rdns_libev_del_write (void *priv_data, void *ev_data);
static void* rdns_libev_add_timer (void *priv_data, double after, void *user_data);
static void* rdns_libev_add_periodic (void *priv_data, double after, void *user_data);
static void rdns_libev_repeat_timer (void *priv_data, void *ev_data);
static void rdns_libev_del_timer (void *priv_data, void *ev_data);

static void
rdns_bind_libev (struct rdns_resolver *resolver, struct ev_loop *loop)
{
	static struct rdns_async_context ev_ctx = {
		.add_read = rdns_libev_add_read,
		.del_read = rdns_libev_del_read,
		.add_write = rdns_libev_add_write,
		.del_write = rdns_libev_del_write,
		.add_timer = rdns_libev_add_timer,
		.add_periodic = rdns_libev_add_periodic,
		.repeat_timer = rdns_libev_repeat_timer,
		.del_timer = rdns_libev_del_timer,
		.cleanup = NULL
	}, *nctx;

	/* XXX: never got freed */
	nctx = malloc (sizeof (struct rdns_async_context));
	if (nctx != NULL) {
		memcpy (nctx, &ev_ctx, sizeof (struct rdns_async_context));
		nctx->data = loop;
	}
	rdns_resolver_async_bind (resolver, nctx);
}

static void
rdns_libev_read_event (struct ev_loop *loop, ev_io *ev, int revents)
{
	rdns_process_read (ev->fd, ev->data);
}

static void
rdns_libev_write_event (struct ev_loop *loop, ev_io *ev, int revents)
{
	rdns_process_retransmit (ev->fd, ev->data);
}

static void
rdns_libev_timer_event (struct ev_loop *loop, ev_timer *ev, int revents)
{
	rdns_process_timer (ev->data);
}

static void
rdns_libev_periodic_event (struct ev_loop *loop, ev_timer *ev, int revents)
{
	rdns_process_periodic (ev->data);
}

static void*
rdns_libev_add_read (void *priv_data, int fd, void *user_data)
{
	ev_io *ev;
	ev = malloc (sizeof (ev_io));
	if (ev != NULL) {
		ev_io_init (ev, rdns_libev_read_event, fd, EV_READ);
		ev->data = user_data;
		ev_io_start (priv_data, ev);
	}
	return ev;
}

static void
rdns_libev_del_read(void *priv_data, void *ev_data)
{
	ev_io *ev = ev_data;
	if (ev != NULL) {
		ev_io_stop (priv_data, ev);
		free (ev);
	}
}
static void*
rdns_libev_add_write (void *priv_data, int fd, void *user_data)
{
	ev_io *ev;
	ev = malloc (sizeof (ev_io));
	if (ev != NULL) {
		ev_io_init (ev, rdns_libev_write_event, fd, EV_WRITE);
		ev->data = user_data;
		ev_io_start (priv_data, ev);
	}
	return ev;
}

static void
rdns_libev_del_write (void *priv_data, void *ev_data)
{
	ev_io *ev = ev_data;
	if (ev != NULL) {
		ev_io_stop (priv_data, ev);
		free (ev);
	}
}

static void*
rdns_libev_add_timer (void *priv_data, double after, void *user_data)
{
	ev_timer *ev;
	ev = malloc (sizeof (ev_timer));
	if (ev != NULL) {
		ev_timer_init (ev, rdns_libev_timer_event, after, after);
		ev->data = user_data;
		ev_timer_start (priv_data, ev);
	}
	return ev;
}

static void*
rdns_libev_add_periodic (void *priv_data, double after, void *user_data)
{
	ev_timer *ev;
	ev = malloc (sizeof (ev_timer));
	if (ev != NULL) {
		ev_timer_init (ev, rdns_libev_periodic_event, after, after);
		ev->data = user_data;
		ev_timer_start (priv_data, ev);
	}
	return ev;
}

static void
rdns_libev_repeat_timer (void *priv_data, void *ev_data)
{
	ev_timer *ev = ev_data;
	if (ev != NULL) {
		ev_timer_again (priv_data, ev);
	}
}

static void
rdns_libev_del_timer (void *priv_data, void *ev_data)
{
	ev_timer *ev = ev_data;
	if (ev != NULL) {
		ev_timer_stop (priv_data, ev);
		free (ev);
	}
}

#endif /* RDNS_EV_H_ */
