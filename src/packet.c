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
#include "dns_private.h"
#include "punycode.h"
#include "packet.h"

void
rdns_allocate_packet (struct rdns_request* req, unsigned int namelen)
{
	namelen += 96 + 2 + 4 + 11; /* EDNS0 RR */
	req->packet = malloc (namelen);
	req->pos = 0;
	req->packet_len = namelen;
}


void
rdns_make_dns_header (struct rdns_request *req)
{
	struct dns_header *header;

	/* Set DNS header values */
	header = (struct dns_header *)req->packet;
	memset (header, 0 , sizeof (struct dns_header));
	header->qid = rdns_permutor_generate_id ();
	header->rd = 1;
	header->qdcount = htons (1);
	header->arcount = htons (1);
	req->pos += sizeof (struct dns_header);
	req->id = header->qid;
}

static bool
rdns_maybe_punycode_label (uint8_t *begin, uint8_t **res, uint8_t **dot, unsigned int *label_len)
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

void
rdns_format_dns_name (struct rdns_request *req, const char *name, unsigned int namelen)
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
		if (rdns_maybe_punycode_label (begin, &name_pos, &dot, &label_len)) {
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

void
rdns_add_rr (struct rdns_request *req, const char *name, enum dns_type type)
{
	uint16_t *p;
	int len = strlen (name);

	rdns_allocate_packet (req, len);
	rdns_make_dns_header (req);
	rdns_format_dns_name (req, name, len);
	p = (uint16_t *)(req->packet + req->pos);
	*p++ = htons (type);
	*p = htons (DNS_C_IN);
	req->pos += sizeof (uint16_t) * 2;
}

void
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
	/* Z 10000000 00000000 to allow dnssec, disabled currently */
	*p16++ = 0;
	/* Length */
	*p16 = 0;
	req->pos += sizeof (uint8_t) + sizeof (uint16_t) * 5;
}
