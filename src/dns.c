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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>

#include "rdns.h"
#include "dns_private.h"
#include "ottery.h"

#define DNS_DEBUG(...) do { } while (0);

static uint16_t
dns_permutor_generate_id (void)
{
	uint16_t id;

	id = ottery_rand_unsigned ();

	return id;
}


struct dns_request_key {
	uint16_t id;
	uint16_t port;
};

#if 0
/** Message compression (waste of resources in case of request) */
struct dns_name_table {
	uint8_t off;
	uint8_t *label;
	uint8_t len;
	UT_hash_handle hh;
};

static bool
try_compress_label (memory_pool_t *pool, uint8_t *target, uint8_t *start, uint8_t len,
		uint8_t *label, struct dns_name_table **table)
{
	struct dns_name_table *found = NULL;
	uint16_t pointer;

	HASH_FIND (hh, *table, label, len, found);
	if (found != NULL) {
		pointer = htons ((uint16_t)found->off | 0xC0);
		memcpy (target, &pointer, sizeof (pointer));
		return true;
	}
	else {
		/* Insert label to list */
		found = memory_pool_alloc (pool, sizeof (struct dns_name_table));
		found->off = target - start;
		found->label = label;
		found->len = len;
		HASH_ADD_KEYPTR (hh, *table, found->label, len, found);
	}

	return false;
}
#endif

/** Packet creating functions */
static void
allocate_packet (struct rdns_request *req, unsigned int namelen)
{
	namelen += 96 /* header */
		+ 2 /* Trailing label */
		+ 4 /* Resource type */
		+ 11; /* EDNS0 RR */
	req->packet = malloc (namelen);
	req->pos = 0;
	req->packet_len = namelen;
}

static void
make_dns_header (struct rdns_request *req)
{
	struct dns_header *header;
	
	/* Set DNS header values */
	header = (struct dns_header *)req->packet;
	memset (header, 0 , sizeof (struct dns_header));
	header->qid = dns_permutor_generate_id ();
	header->rd = 1;
	header->qdcount = htons (1);
	header->arcount = htons (1);
	req->pos += sizeof (struct dns_header);
	req->id = header->qid;
}

static bool
maybe_punycode_label (uint8_t *begin, uint8_t **res, uint8_t **dot, unsigned int *label_len)
{
	bool ret = false;
	uint8_t *p = begin;

	*dot = NULL;

	while (*p) {
		if (*p == '.') {
			*dot = p;
			break;
		}
		else if ((*p) & 0x80) {
			ret = true;
		}
		p ++;
	}

	if (*p) {
		*res = p - 1;
		*label_len = p - begin;
	}
	else {
		*res = p;
		*label_len = p - begin;
	}

	return ret;
}

static void
format_dns_name (struct rdns_request *req, const char *name, unsigned int namelen)
{
	uint8_t *pos = req->packet + req->pos, *end, *dot, *name_pos, *begin;
	unsigned int remain = req->packet_len - req->pos - 5, label_len;
	uint32_t *uclabel;
	size_t punylabel_len, uclabel_len;
	uint8_t tmp_label[DNS_D_MAXLABEL];

	if (namelen == 0) {
		namelen = strlen (name);
	}
	
	begin = (uint8_t *)name;
	end = (uint8_t *)name + namelen;
	for (;;) {
		/* Check label for unicode characters */
		if (maybe_punycode_label (begin, &name_pos, &dot, &label_len)) {
			/* Convert to ucs4 */
			if (rdns_utf8_to_ucs4 ((char *)begin, label_len, &uclabel, &uclabel_len) == 0) {
				punylabel_len = DNS_D_MAXLABEL;

				rdns_punycode_label_toascii (uclabel, uclabel_len, (char *)tmp_label, &punylabel_len);
				/* Try to compress name */
				*pos++ = (uint8_t)punylabel_len;
				memcpy (pos, tmp_label, punylabel_len);
				free (uclabel);
				pos += punylabel_len;
				if (dot) {
					remain -= label_len + 1;
					begin = dot + 1;
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}
		else {
			if (dot) {
				if (label_len > DNS_D_MAXLABEL) {
					DNS_DEBUG ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					label_len = remain - 1;
					DNS_DEBUG ("no buffer remain for constructing query, strip to %ud", label_len);
				}
				if (label_len == 0) {
					/* Two dots in order, skip this */
					DNS_DEBUG ("name contains two or more dots in a row, replace it with one dot");
					begin = dot + 1;
					continue;
				}
				*pos++ = (uint8_t)label_len;
				memcpy (pos, begin, label_len);
				pos += label_len;
				remain -= label_len + 1;
				begin = dot + 1;
			}
			else {
				if (label_len == 0) {
					/* If name is ended with dot */
					break;
				}
				if (label_len > DNS_D_MAXLABEL) {
					DNS_DEBUG ("dns name component is longer than 63 bytes, should be stripped");
					label_len = DNS_D_MAXLABEL;
				}
				if (remain < label_len + 1) {
					label_len = remain - 1;
					DNS_DEBUG ("no buffer remain for constructing query, strip to %ud", label_len);
				}
				*pos++ = (uint8_t)label_len;
				memcpy (pos, begin, label_len);
				pos += label_len;
				break;
			}
		}
		if (remain == 0) {
			DNS_DEBUG ("no buffer space available, aborting");
			break;
		}
	}
	/* Termination label */
	*pos = '\0';
	req->pos += pos - (req->packet + req->pos) + 1;
}

static void
rdns_add_rr (struct rdns_request *req, const char *name, enum dns_type type)
{
	uint16_t *p;
	int len = strlen (name);

	allocate_packet (req, len);
	make_dns_header (req);
	format_dns_name (req, name, len);
	p = (uint16_t *)(req->packet + req->pos);
	*p++ = htons (type);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (uint16_t) * 2;
}

static void
rdns_add_edns0 (struct rdns_request *req)
{
	uint8_t *p8;
	uint16_t *p16;

	p8 = (uint8_t *)(req->packet + req->pos);
	*p8 = '\0'; /* Name is root */
	p16 = (uint16_t *)(req->packet + req->pos + 1);
	*p16++ = htons (DNS_T_OPT);
	/* UDP packet length */
	*p16++ = htons (UDP_PACKET_SIZE);
	/* Extended rcode 00 00 */
	*p16++ = 0;
	/* Z 10000000 00000000 to allow dnssec */
	p8 = (uint8_t *)p16++;
	/* Not a good time for DNSSEC */
	*p8 = 0x00;
	/* Length */
	*p16 = 0;
	req->pos += sizeof (uint8_t) + sizeof (uint16_t) * 5;
}

static int
rdns_send_request (struct rdns_request *req, int fd, bool new_req)
{
	int r;
	struct rdns_server *serv = req->io->srv;
	struct rdns_resolver *resolver = req->resolver;
	struct rdns_request *tmp;
	struct dns_header *header;
	const int max_id_cycles = 32;

	/* Find ID collision */
	if (new_req) {
		r = 0;
		HASH_FIND_INT (req->io->requests, &req->id, tmp);
		while (tmp != NULL) {
			/* Check for unique id */
			header = (struct dns_header *)req->packet;
			header->qid = dns_permutor_generate_id ();
			req->id = header->qid;
			if (++r > max_id_cycles) {
				return -1;
			}
			HASH_FIND_INT (req->io->requests, &req->id, tmp);
		}
	}

	r = send (fd, req->packet, req->pos, 0);
	if (r == -1) {
		if (errno == EAGAIN || errno == EINTR) {
			if (new_req) {
				/* Write when socket is ready */
				HASH_ADD_INT (req->io->requests, id, req);
				req->async_event = resolver->async.add_write (resolver->async.data,
					fd, req);
			}
			/*
			 * If request is already processed then the calling function
			 * should take care about events processing
			 */
			return 0;
		} 
		else {
			DNS_DEBUG ("send failed: %s for server %s", strerror (errno), serv->name);
			return -1;
		}
	}
	
	if (new_req) {
		/* Add request to hash table */
		HASH_ADD_INT (req->io->requests, id, req);
		/* Fill timeout */
		req->async_event = resolver->async.add_timer (resolver->async.data,
				req->timeout, req);
		req->state = RDNS_REQUEST_SENT;
	}

	return 1;
}

static uint8_t *
decompress_label (uint8_t *begin, uint16_t *len, uint16_t max)
{
	uint16_t offset = (*len);

	if (offset > max) {
		DNS_DEBUG ("invalid DNS compression pointer: %d max is %d", (int)offset, (int)max);
		return NULL;
	}
	*len = *(begin + offset);
	return begin + offset;
}

#define UNCOMPRESS_DNS_OFFSET(p) (((*(p)) ^ DNS_COMPRESSION_BITS) << 8) + *((p) + 1)

static uint8_t *
dns_request_reply_cmp (struct rdns_request *req, uint8_t *in, int len)
{
	uint8_t *p, *c, *l1, *l2;
	uint16_t len1, len2;
	int decompressed = 0;

	/* QR format:
	 * labels - len:octets
	 * null label - 0
	 * class - 2 octets
	 * type - 2 octets
	 */
	
	/* In p we would store current position in reply and in c - position in request */
	p = in;
	c = req->packet + sizeof (struct dns_header);

	for (;;) {
		/* Get current label */
		len1 = *p;
		len2 = *c;
		if (p - in > len) {
			DNS_DEBUG ("invalid dns reply");
			return NULL;
		}
		/* This may be compressed, so we need to decompress it */
		if (len1 & DNS_COMPRESSION_BITS) {
			len1 = UNCOMPRESS_DNS_OFFSET(p);
			l1 = decompress_label (in, &len1, len);
			if (l1 == NULL) {
				return NULL;
			}
			decompressed ++;
			l1 ++;
			p += 2;
		}
		else {
			l1 = ++p;
			p += len1;
		}
		if (len2 & DNS_COMPRESSION_BITS) {
			len2 = UNCOMPRESS_DNS_OFFSET(p);
			l2 = decompress_label (req->packet, &len2, len);
			if (l2 == NULL) {
				DNS_DEBUG ("invalid DNS pointer");
				return NULL;
			}
			decompressed ++;
			l2 ++;
			c += 2;
		}
		else {
			l2 = ++c;
			c += len2;
		}
		if (len1 != len2) {
			return NULL;
		}
		if (len1 == 0) {
			break;
		}

		if (memcmp (l1, l2, len1) != 0) {
			return NULL;
		}
		if (decompressed == 2) {
			break;
		}
	}

	/* p now points to the end of QR section */
	/* Compare class and type */
	if (memcmp (p, c, sizeof (uint16_t) * 2) == 0) {
		return p + sizeof (uint16_t) * 2;
	}
	return NULL;
}

#define MAX_RECURSION_LEVEL 10

static bool
dns_parse_labels (uint8_t *in, char **target, uint8_t **pos, struct rdns_reply *rep,
		int *remain, bool make_name)
{
	uint16_t namelen = 0;
	uint8_t *p = *pos, *begin = *pos, *l, *t, *end = *pos + *remain, *new_pos = *pos;
	uint16_t llen;
	int length = *remain, new_remain = *remain;
	int ptrs = 0, labels = 0;
	bool got_compression = false;

	/* First go through labels and calculate name length */
	while (p - begin < length) {
		if (ptrs > MAX_RECURSION_LEVEL) {
			msg_warn ("dns pointers are nested too much");
			return false;
		}
		llen = *p;
		if (llen == 0) {
			if (!got_compression) {
				/* In case of compression we have already decremented the processing position */
				new_remain -= sizeof (uint8_t);
				new_pos += sizeof (uint8_t);
			}
			break;
		}
		else if ((llen & DNS_COMPRESSION_BITS)) {
			if (end - p > 1) {
				ptrs ++;
				llen = UNCOMPRESS_DNS_OFFSET(p);
				l = decompress_label (in, &llen, end - in);
				if (l == NULL) {
					DNS_DEBUG ("invalid DNS pointer");
					return false;
				}
				if (!got_compression) {
					/* Our label processing is finished actually */
					new_remain -= sizeof (uint16_t);
					new_pos += sizeof (uint16_t);
					got_compression = true;
				}
				if (l < in || l > begin + length) {
					msg_warn  ("invalid pointer in DNS packet");
					return false;
				}
				begin = l;
				length = end - begin;
				p = l + *l + 1;
				namelen += *l;
				labels ++;
			}
			else {
				msg_warn ("DNS packet has incomplete compressed label, input length: %d bytes, remain: %d",
						*remain, new_remain);
				return false;
			}
		}
		else {
			namelen += llen;
			p += llen + 1;
			labels ++;
			if (!got_compression) {
				new_remain -= llen + 1;
				new_pos += llen + 1;
			}
		}
	}

	if (!make_name) {
		goto end;
	}
	*target = malloc (namelen + labels + 3);
	t = (uint8_t *)*target;
	p = *pos;
	begin = *pos;
	length = *remain;
	/* Now copy labels to name */
	while (p - begin < length) {
		llen = *p;
		if (llen == 0) {
			break;
		}
		else if (llen & DNS_COMPRESSION_BITS) {
			llen = UNCOMPRESS_DNS_OFFSET(p);
			l = decompress_label (in, &llen, end - in);
			begin = l;
			length = end - begin;
			p = l + *l + 1;
			memcpy (t, l + 1, *l);
			t += *l;
			*t ++ = '.';
		}
		else {
			memcpy (t, p + 1, *p);
			t += *p;
			*t ++ = '.';
			p += *p + 1;
		}
	}
	*(t - 1) = '\0';
end:
	*remain = new_remain;
	*pos = new_pos;

	return true;
}

#define GET16(x) do {(x) = ((*p) << 8) + *(p + 1); p += sizeof (uint16_t); *remain -= sizeof (uint16_t); } while(0)
#define GET32(x) do {(x) = ((*p) << 24) + ((*(p + 1)) << 16) + ((*(p + 2)) << 8) + *(p + 3); p += sizeof (uint32_t); *remain -= sizeof (uint32_t); } while(0)
#define SKIP(type) do { p += sizeof(type); *remain -= sizeof(type); } while (0)

static int
dns_parse_rr (uint8_t *in, struct rdns_reply_entry *elt, uint8_t **pos, struct rdns_reply *rep, int *remain)
{
	uint8_t *p = *pos, parts;
	uint16_t type, datalen, txtlen, copied, ttl;
	bool parsed = false;

	/* Skip the whole name */
	if (! dns_parse_labels (in, NULL, &p, rep, remain, false)) {
		DNS_DEBUG ("bad RR name");
		return -1;
	}
	if (*remain < (int)sizeof (uint16_t) * 6) {
		DNS_DEBUG ("stripped dns reply: %d bytes remain", *remain);
		return -1;
	}
	GET16 (type);
	GET16 (ttl);
	/* Skip class */
	SKIP (uint32_t);
	GET16 (datalen);
	/* Now p points to RR data */
	switch (type) {
	case DNS_T_A:
		if (!(datalen & 0x3) && datalen <= *remain) {
			memcpy (&elt->content.a.addr, p, sizeof (struct in_addr));
			p += datalen;
			*remain -= datalen;
			parsed = true;
			elt->type = DNS_REQUEST_A;
		}
		else {
			DNS_DEBUG ("corrupted A record");
			return -1;
		}
		break;
	case DNS_T_AAAA:
		if (datalen == sizeof (struct in6_addr) && datalen <= *remain) {
			memcpy (&elt->content.aaa.addr, p, sizeof (struct in6_addr));
			p += datalen;
			*remain -= datalen;
			parsed = true;
			elt->type = DNS_REQUEST_AAA;
		}
		else {
			DNS_DEBUG ("corrupted AAAA record");
			return -1;
		}
		break;
	case DNS_T_PTR:
		if (! dns_parse_labels (in, &elt->content.ptr.name, &p, rep, remain, true)) {
			DNS_DEBUG ("invalid labels in PTR record");
			return -1;
		}
		parsed = true;
		elt->type = DNS_REQUEST_PTR;
		break;
	case DNS_T_MX:
		GET16 (elt->content.mx.priority);
		if (! dns_parse_labels (in, &elt->content.mx.name, &p, rep, remain, true)) {
			DNS_DEBUG ("invalid labels in MX record");
			return -1;
		}
		parsed = true;
		elt->type = DNS_REQUEST_MX;
		break;
	case DNS_T_TXT:
	case DNS_T_SPF:
		elt->content.txt.data = malloc (datalen + 1);
		/* Now we should compose data from parts */
		copied = 0;
		parts = 0;
		while (copied + parts < datalen) {
			txtlen = *p;
			if (txtlen + copied + parts <= datalen) {
				parts ++;
				memcpy (elt->content.txt.data + copied, p + 1, txtlen);
				copied += txtlen;
				p += txtlen + 1;
				*remain -= txtlen + 1;
			}
			else {
				break;
			}
		}
		*(elt->content.txt.data + copied) = '\0';
		parsed = true;
		elt->type = DNS_REQUEST_TXT;
		break;
	case DNS_T_SRV:
		if (p - *pos > (int)(*remain - sizeof (uint16_t) * 3)) {
			DNS_DEBUG ("stripped dns reply while reading SRV record");
			return -1;
		}
		GET16 (elt->content.srv.priority);
		GET16 (elt->content.srv.weight);
		GET16 (elt->content.srv.port);
		if (! dns_parse_labels (in, &elt->content.srv.target, &p, rep, remain, true)) {
			DNS_DEBUG ("invalid labels in SRV record");
			return -1;
		}
		parsed = true;
		elt->type = DNS_REQUEST_SRV;
		break;
	case DNS_T_CNAME:
		/* Skip cname records */
		p += datalen;
		*remain -= datalen;
		break;
	default:
		DNS_DEBUG ("unexpected RR type: %d", type);
		p += datalen;
		*remain -= datalen;
		break;
	}
	*pos = p;

	if (parsed) {
		elt->ttl = ttl;
		return 1;
	}
	return 0;
}

static bool
dns_parse_reply (int sock, uint8_t *in, int r, struct rdns_resolver *resolver,
		struct rdns_request **req_out, struct rdns_reply **_rep)
{
	struct dns_header *header = (struct dns_header *)in;
	struct rdns_request      *req;
	struct rdns_reply        *rep;
	struct rdns_io_channel   *ioc;
	struct rdns_reply_entry      *elt;
	uint8_t                         *pos;
	int id;
	int                            i, t;
	
	/* First check header fields */
	if (header->qr == 0) {
		DNS_DEBUG ("got request while waiting for reply");
		return false;
	}

	/* Find io channel */
	HASH_FIND_INT (resolver->io_channels, &sock, ioc);
	if (ioc == NULL) {
		DNS_DEBUG ("io channel is not found for this resolver: %d", sock);
		return false;
	}

	/* Now try to find corresponding request */
	id = header->qid;
	HASH_FIND_INT (ioc->requests, &id, req);
	if (req == NULL) {
		/* No such requests found */
		DNS_DEBUG ("DNS request with id %d has not been found for IO channel", (int)id);
		return false;
	}
	*req_out = req;
	/* 
	 * Now we have request and query data is now at the end of header, so compare
	 * request QR section and reply QR section
	 */
	if ((pos = dns_request_reply_cmp (req, in + sizeof (struct dns_header),
			r - sizeof (struct dns_header))) == NULL) {
		DNS_DEBUG ("DNS request with id %d is for different query, ignoring", (int)id);
		return false;
	}
	/*
	 * Now pos is in answer section, so we should extract data and form reply
	 */
	rep = malloc (sizeof (struct rdns_reply));
	rep->request = req;
	rep->entries = NULL;
	rep->code = header->rcode;

	if (rep->code == DNS_RC_NOERROR) {
		r -= pos - in;
		/* Extract RR records */
		for (i = 0; i < ntohs (header->ancount); i ++) {
			elt = malloc (sizeof (struct rdns_reply_entry));
			t = dns_parse_rr (in, elt, &pos, rep, &r);
			if (t == -1) {
				free (elt);
				DNS_DEBUG ("incomplete reply");
				break;
			}
			else if (t == 1) {
				DL_APPEND (rep->entries, elt);
			}
		}
	}
	
	*_rep = rep;
	return true;
}


void
rdns_process_read (int fd, void *arg)
{
	struct rdns_resolver     *resolver = arg;
	struct rdns_request      *req = NULL;
	int                            r;
	struct rdns_reply        *rep;
	uint8_t                          in[UDP_PACKET_SIZE];

	/* This function is called each time when we have data on one of server's sockets */
	
	/* First read packet from socket */
	r = read (fd, in, sizeof (in));
	if (r > (int)(sizeof (struct dns_header) + sizeof (struct dns_query))) {
		if (dns_parse_reply (fd, in, r, resolver, &req, &rep)) {
			rdns_request_ref (req);
			req->func (rep, req->arg);
			rdns_request_unref (req);
		}
	}
}

void
rdns_process_timer (void *arg)
{
	struct rdns_request *req = (struct rdns_request *)arg;
	struct rdns_resolver *resolver;
	int r;

	resolver = req->resolver;

	req->retransmits ++;
	if (req->retransmits > resolver->max_retransmits) {
		/* XXX: call the callback */
		rdns_request_unref (req);
		return;
	}

	r = rdns_send_request (req, req->io->sock, false);
	if (r == 0) {
		/* Retransmit one more time */
		resolver->async.del_timer (resolver->async.data,
					req->async_event);
		req->async_event = resolver->async.add_write (resolver->async.data,
				req->io->sock, req);
		req->state = RDNS_REQUEST_REGISTERED;
	}
	else if (r == -1) {
		/* XXX: call the callback */
		rdns_request_unref (req);
	}
	else {
		resolver->async.repeat_timer (resolver->async.data, req->async_event);
	}
}

void
rdns_process_retransmit (int fd, void *arg)
{
	struct rdns_request *req = (struct rdns_request *)arg;
	struct rdns_resolver *resolver;
	int r;

	resolver = req->resolver;

	resolver->async.del_write (resolver->async.data,
			req->async_event);

	r = rdns_send_request (req, fd, false);

	if (r == 0) {
		/* Retransmit one more time */
		req->async_event = resolver->async.add_write (resolver->async.data,
						fd, req);
		req->state = RDNS_REQUEST_REGISTERED;
	}
	else if (r == -1) {
		/* XXX: call the callback */
		rdns_request_unref (req);
	}
	else {
		req->async_event = resolver->async.add_timer (resolver->async.data,
			req->timeout, req);
		req->state = RDNS_REQUEST_SENT;
	}
}

static void
rdns_request_free (struct rdns_request *req)
{
	if (req != NULL) {
		if (req->io != NULL && req->state > RDNS_REQUEST_NEW) {
			/* Remove from id hashes */
			HASH_DEL (req->io->requests, req);
		}
		if (req->packet != NULL) {
			free (req->packet);
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

struct rdns_request*
rdns_make_request_full (
		struct rdns_resolver *resolver,
		dns_callback_type cb,
		void *cbdata,
		double timeout,
		unsigned int repeats,
		const char *name,
		unsigned int queries,
		...
		)
{
	va_list args;
	struct rdns_request *req;
	struct rdns_server *serv;
	struct in_addr *addr;
	int r, type;
	unsigned int i;

	if (!resolver->initialized) {
		return NULL;
	}

	req = malloc (sizeof (struct rdns_request));
	if (req == NULL) {
		return NULL;
	}

	req->resolver = resolver;
	req->func = cb;
	req->arg = cbdata;
	req->ref = 1;
	
	va_start (args, queries);
	for (i = 0; i < queries; i ++) {
		type = va_arg (args, int);
		switch (type) {
		case DNS_REQUEST_PTR:
			rdns_add_rr (req, name, DNS_T_PTR);
			break;
		case DNS_REQUEST_MX:
			rdns_add_rr (req, name, DNS_T_MX);
			break;
		case DNS_REQUEST_A:
			rdns_add_rr (req, name, DNS_T_A);
			break;
		case DNS_REQUEST_AAA:
			rdns_add_rr (req, name, DNS_T_AAAA);
			break;
		case DNS_REQUEST_TXT:
			rdns_add_rr (req, name, DNS_T_TXT);
			break;
		case DNS_REQUEST_SPF:
			rdns_add_rr (req, name, DNS_T_SPF);
			break;
		case DNS_REQUEST_SRV:
			rdns_add_rr (req, name, DNS_T_SRV);
			break;
		}
	}
	va_end (args);

	/* Add EDNS RR */
	rdns_add_edns0 (req);

	req->retransmits = 0;
	req->timeout = timeout;
	req->io = NULL;
	req->state = RDNS_REQUEST_NEW;

	UPSTREAM_SELECT_ROUND_ROBIN (resolver->servers, serv);

	if (serv == NULL) {
		DNS_DEBUG ("cannot find suitable server for request");
		rdns_request_unref (req);
		return NULL;
	}
	
	/* Now select IO channel */

	req->io = serv->cur_io_channel;
	if (req->io == NULL) {
		DNS_DEBUG ("cannot find suitable io channel for the server %s", serv->name);
		rdns_request_unref (req);
		return NULL;
	}
	serv->cur_io_channel = serv->cur_io_channel->next;
	
	/* Now send request to server */
	r = rdns_send_request (req, req->io->sock, true);

	if (r == -1) {
		rdns_request_unref (req);
		return NULL;
	}

	return req;
}

bool
rdns_resolver_init (struct rdns_resolver *resolver)
{
	unsigned int i;
	struct rdns_server *serv;
	struct rdns_io_channel *ioc;

	if (!resolver->async_binded) {
		return false;
	}
	
	/* Now init io channels to all servers */
	UPSTREAM_FOREACH (resolver->servers, serv) {
		for (i = 0; i < serv->io_cnt; i ++) {
			ioc = calloc (1, sizeof (struct rdns_io_channel));
			ioc->sock = make_universal_socket (serv->name, dns_port, SOCK_DGRAM);
			if (ioc->sock == -1) {
				return false;
			}
			else {
				ioc->srv = serv;
				ioc->resolver = resolver;
				ioc->async_io = resolver->async.add_read (resolver->async.data,
						ioc->sock, ioc);
				serv->cur_io_channel = ioc;
				HASH_ADD_INT (resolver->io_channels, sock, ioc);
			}
		}
	}

	resolver->initialized = true;

	return true;
}

bool
rdns_resolver_add_server (struct rdns_resolver *resolver,
		const char *name, int priority)
{
	struct rdns_server *serv;
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} addr;

	if (inet_pton (AF_INET, name, &addr) == 0 &&
		inet_pton (AF_INET6, name, &addr) == 0) {
		/* Invalid IP */
		return false;
	}

	serv = calloc (1, sizeof (struct rdns_server));
	if (serv == NULL) {
		return false;
	}
	serv->name = strdup (name);
	if (serv->name == NULL) {
		free (serv);
		return false;
	}

	UPSTREAM_ADD (resolver->servers, serv, priority);

	return true;
}

struct rdns_resolver *
rdns_resolver_new (void)
{
	struct rdns_resolver     *new;

	new = calloc (1, sizeof (struct rdns_resolver));

	return new;
}

void
rdns_resolver_async_bind (struct rdns_resolver *resolver,
		struct rdns_async_context *ctx)
{
	if (resolver != NULL && ctx != NULL) {
		resolver->async = *ctx;
		resolver->async_binded = true;
	}
}

const char *
dns_strerror (enum dns_rcode rcode)
{
	rcode &= 0xf;
	static char numbuf[16];

	if ('\0' == dns_rcodes[rcode][0]) {
		rdns_snprintf (numbuf, sizeof (numbuf), "UNKNOWN: %d", (int)rcode);
		return numbuf;
	}
	return dns_rcodes[rcode];
}

const char *
dns_strtype (enum rdns_request_type type)
{
	return dns_types[type];
}
