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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>

#include "ottery.h"
#include "util.h"

static int
rdns_make_socket_nonblocking (int fd)
{
	int                            ofl;

	ofl = fcntl (fd, F_GETFL, 0);

	if (fcntl (fd, F_SETFL, ofl | O_NONBLOCK) == -1) {
		return -1;
	}
	return 0;
}

static int
rdns_make_inet_socket (int type, struct addrinfo *addr)
{
	int fd, r, on = 1, s_error;
	socklen_t optlen;
	struct addrinfo *cur;

	cur = addr;
	while (cur) {
		/* Create socket */
		fd = socket (cur->ai_family, type, 0);
		if (fd == -1) {
			goto out;
		}

		if (rdns_make_socket_nonblocking (fd) < 0) {
			goto out;
		}

		/* Set close on exec */
		if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
			goto out;
		}

		r = connect (fd, cur->ai_addr, cur->ai_addrlen);

		if (r == -1) {
			if (errno != EINPROGRESS) {
				goto out;
			}
		}
		else {
			/* Still need to check SO_ERROR on socket */
			optlen = sizeof (s_error);
			getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
			if (s_error) {
				errno = s_error;
				goto out;
			}
		}
		break;
out:
		if (fd != -1) {
			close (fd);
		}
		fd = -1;
		cur = cur->ai_next;
	}
	return (fd);
}

static int
rdns_make_unix_socket (const char *path, struct sockaddr_un *addr, int type)
{
	int fd = -1, s_error, r, serrno, on = 1;
	struct stat st;
	socklen_t optlen;

	if (path == NULL) {
		return -1;
	}

	addr->sun_family = AF_UNIX;

	memset (addr->sun_path, 0, sizeof (addr->sun_path));
	memccpy (addr->sun_path, path, 0, sizeof (addr->sun_path) - 1);
#ifdef FREEBSD
	addr->sun_len = SUN_LEN (addr);
#endif

	fd = socket (PF_LOCAL, type, 0);

	if (fd == -1) {
		return -1;
	}

	if (rdns_make_socket_nonblocking (fd) < 0) {
		goto out;
	}

	/* Set close on exec */
	if (fcntl (fd, F_SETFD, FD_CLOEXEC) == -1) {
		goto out;
	}

	r = connect (fd, (struct sockaddr *)addr, SUN_LEN (addr));

	if (r == -1) {
		if (errno != EINPROGRESS) {
			goto out;
		}
	}
	else {
		/* Still need to check SO_ERROR on socket */
		optlen = sizeof (s_error);
		getsockopt (fd, SOL_SOCKET, SO_ERROR, (void *)&s_error, &optlen);
		if (s_error) {
			errno = s_error;
			goto out;
		}
	}

	return (fd);

  out:
	serrno = errno;
	if (fd != -1) {
		close (fd);
	}
	errno = serrno;
	return (-1);
}

/**
 * Make a universal socket
 * @param credits host, ip or path to unix socket
 * @param port port (used for network sockets)
 * @param async make this socket asynced
 * @param is_server make this socket as server socket
 * @param try_resolve try name resolution for a socket (BLOCKING)
 */
int
rdns_make_client_socket (const char *credits, uint16_t port,
		int type)
{
	struct sockaddr_un              un;
	struct stat                     st;
	struct addrinfo                 hints, *res;
	int                             r;
	char                            portbuf[8];

	if (*credits == '/') {
		r = stat (credits, &st);
		if (r == -1) {
			/* Unix socket doesn't exists it must be created first */
			errno = ENOENT;
			return -1;
		}
		else {
			if ((st.st_mode & S_IFSOCK) == 0) {
				/* Path is not valid socket */
				errno = EINVAL;
				return -1;
			}
			else {
				return rdns_make_unix_socket (credits, &un, type);
			}
		}
	}
	else {
		/* TCP related part */
		memset (&hints, 0, sizeof (hints));
		hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
		hints.ai_socktype = type; /* Type of the socket */
		hints.ai_flags = 0;
		hints.ai_protocol = 0;           /* Any protocol */
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;

		snprintf (portbuf, sizeof (portbuf), "%d", (int)port);
		if ((r = getaddrinfo (credits, portbuf, &hints, &res)) == 0) {
			r = rdns_make_inet_socket (type, res);
			freeaddrinfo (res);
			return r;
		}
		else {
			return -1;
		}
	}

	/* Not reached */
	return -1;
}

const char *
rdns_strerror (enum dns_rcode rcode)
{
	rcode &= 0xf;
	static char numbuf[16];

	if ('\0' == dns_rcodes[rcode][0]) {
		snprintf (numbuf, sizeof (numbuf), "UNKNOWN: %d", (int)rcode);
		return numbuf;
	}
	return dns_rcodes[rcode];
}

const char *
rdns_strtype (enum rdns_request_type type)
{
	return dns_types[type];
}

uint16_t
rdns_permutor_generate_id (void)
{
	uint16_t id;

	id = ottery_rand_unsigned ();

	return id;
}


static void
rdns_reply_free (struct rdns_reply *rep)
{
	struct rdns_reply_entry *entry, *tmp;

	LL_FOREACH_SAFE (rep->entries, entry, tmp) {
		switch (entry->type) {
		case DNS_T_PTR:
			free (entry->content.ptr.name);
			break;
		case DNS_T_MX:
			free (entry->content.mx.name);
			break;
		case DNS_T_TXT:
		case DNS_T_SPF:
			free (entry->content.txt.data);
			break;
		case DNS_T_SRV:
			free (entry->content.srv.target);
			break;
		}
		free (entry);
	}
	free (rep);
}

static void
rdns_request_free (struct rdns_request *req)
{
	if (req != NULL) {
		if (req->io != NULL && req->state > RDNS_REQUEST_NEW) {
			/* Remove from id hashes */
			HASH_DEL (req->io->requests, req);
			rdns_ioc_unref (req->io, req->async);
		}
		if (req->packet != NULL) {
			free (req->packet);
		}
		if (req->reply != NULL) {
			rdns_reply_free (req->reply);
		}
		if (req->state >= RDNS_REQUEST_SENT) {
			/* Remove timer */
			req->async->del_timer (req->async->data,
					req->async_event);
		}
		else if (req->state == RDNS_REQUEST_REGISTERED) {
			/* Remove retransmit event */
			req->async->del_write (req->async->data,
					req->async_event);
		}
		if (req->network_plugin_data != NULL) {
			req->resolver->network_plugin->cb.network_plugin.finish_cb (
					req, req->resolver->network_plugin->data);
		}
		free (req);
	}
}

struct rdns_request*
rdns_request_ref (struct rdns_request *req)
{
	req->ref ++;
	return req;
}

void
rdns_request_unref (struct rdns_request *req)
{
	if (--req->ref <= 0) {
		rdns_request_free (req);
	}
}

static void
rdns_ioc_free (struct rdns_io_channel *ioc, struct rdns_async_context *async)
{
	struct rdns_request *req, *rtmp;

	HASH_ITER (hh, ioc->requests, req, rtmp) {
		HASH_DELETE (hh, ioc->requests, req);
		rdns_request_unref (req);
	}
	async->del_read (async->data, ioc->async_io);
	close (ioc->sock);
	free (ioc);
}

struct rdns_io_channel *
rdns_ioc_ref (struct rdns_io_channel *ioc)
{
	ioc->ref ++;
	return ioc;
}

void
rdns_ioc_unref (struct rdns_io_channel *ioc, struct rdns_async_context *async)
{
	if (--ioc->ref <= 0) {
		rdns_ioc_free (ioc, async);
	}
}
