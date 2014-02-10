/* Copyright (c) 2014, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
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

#include "rdns.h"
#include "rdns_ev.h"
#include "rdns_event.h"
#include <stdio.h>

static int remain_tests = 0;

static void
rdns_regress_callback (struct rdns_reply *reply, void *arg)
{
	printf ("got result for host: %s\n", (const char *)arg);
	rdns_request_unref (reply->request);

	if (--remain_tests == 0) {
		rdns_resolver_destroy (reply->resolver);
	}
}

static void
rdns_test_a (struct rdns_resolver *resolver)
{
	const char *names[] = {
			"google.com",
			"github.com",
			"freebsd.org",
			"kernel.org",
			"www.ник.рф",
			NULL
	};
	const char **cur;

	for (cur = names; *cur != NULL; cur ++) {
		rdns_make_request_full (resolver, rdns_regress_callback, *cur, 1.0, 2, *cur, 1, DNS_REQUEST_A);
		remain_tests ++;
	}
}

int
main (int argc, char **argv)
{
	struct rdns_resolver *resolver_ev, *resolver_event;
	struct ev_loop *loop;
	struct event_base *base;

	loop = ev_default_loop (0);
	base = event_init ();

	resolver_ev = rdns_resolver_new ();
	rdns_bind_libev (resolver_ev, loop);
	/* Google and opendns */
	rdns_resolver_add_server (resolver_ev, "8.8.8.8", 0);
	rdns_resolver_add_server (resolver_ev, "208.67.222.222", 0);

	resolver_event = rdns_resolver_new ();
	rdns_bind_libevent (resolver_event, base);
	rdns_resolver_add_server (resolver_event, "208.67.222.222", 0);
	rdns_resolver_add_server (resolver_event, "8.8.8.8", 0);

	rdns_resolver_init (resolver_ev);
	rdns_resolver_init (resolver_event);

	rdns_test_a (resolver_ev);
	ev_loop (loop, 0);

	rdns_test_a (resolver_event);
	event_base_loop (base, 0);


	return 0;
}
