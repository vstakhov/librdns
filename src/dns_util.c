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
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>

int
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
	int                            fd, r, optlen, on = 1, s_error;
	struct addrinfo               *cur;

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

int
rdns_make_unix_socket (const char *path, struct sockaddr_un *addr, int type)
{
	int                            fd = -1, s_error, r, optlen, serrno, on = 1;
	struct stat                     st;

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
