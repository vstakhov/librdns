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

#ifndef DNS_PRIVATE_H_
#define DNS_PRIVATE_H_

#include "uthash.h"
#include "utlist.h"
#include "dns.h"
#include "upstream.h"

/* Upstream timeouts */
#define DEFAULT_UPSTREAM_ERROR_TIME 10
#define DEFAULT_UPSTREAM_DEAD_TIME 300
#define DEFAULT_UPSTREAM_MAXERRORS 10

static const unsigned base = 36;
static const unsigned t_min = 1;
static const unsigned t_max = 26;
static const unsigned skew = 38;
static const unsigned damp = 700;
static const unsigned initial_n = 128;
static const unsigned initial_bias = 72;

static const int dns_port = 53;

#define UDP_PACKET_SIZE 4096

#define DNS_COMPRESSION_BITS 0xC0

#define DNS_D_MAXLABEL  63      /* + 1 '\0' */
#define DNS_D_MAXNAME   255     /* + 1 '\0' */

#define RESOLV_CONF "/etc/resolv.conf"

/**
 * Represents DNS server
 */
struct rdns_server {
	char *name; /**< name of DNS server                                         */

	struct rdns_io_channel *io_channels;
	struct rdns_io_channel *cur_io_channel;

	unsigned int io_cnt;

	upstream_entry_t up;
};

struct rdns_request {
	struct rdns_resolver *resolver;
	struct rdns_io_channel *io;

	struct timeval tv;
	unsigned int retransmits;

	int id;
	const char *requested_name;

	uint8_t *packet;
	off_t pos;
	unsigned int packet_len;

	dns_callback_type func;
	void *arg;

	void *async_event;

	UT_hash_handle hh;
};

/**
 * IO channel for a specific DNS server
 */
struct rdns_io_channel {
	struct rdns_server *srv;
	struct rdns_resolver *resolver;
	int sock; /**< persistent socket                                          */
	void *async_io; /** async opaque ptr */
	struct rdns_request *requests; /**< requests in flight                                         */
	struct rdns_io_channel *prev, *next;
	unsigned int ref;
	bool want_reinit;
	UT_hash_handle hh;
};



struct rdns_resolver {
	struct rdns_server *servers;
	unsigned int request_timeout;
	struct rdns_io_channel *io_channels; /**< hash of io chains indexed by socket        */
	struct {
		void *data;
		void* (*add_read)(void *priv_data, void *user_data);
		void (*del_read)(void *priv_data, void *ev_data);
		void* (*add_write)(void *priv_data, void *user_data);
		void (*del_write)(void *priv_data, void *ev_data);
		void* (*add_timer)(void *priv_data, double after, void *user_data);
		void (*repeat_timer)(void *priv_data, void *ev_data);
		void (*del_timer)(void *priv_data, void *ev_data);
		void (*cleanup)(void *priv_data);
	} async; /** async callbacks */
	bool async_binded;
	bool initialized;
};

struct dns_header;
struct dns_query;

/* Internal DNS structs */

struct dns_header {
	unsigned int qid :16;

#if BYTE_ORDER == BIG_ENDIAN
	unsigned int qr:1;
	unsigned int opcode:4;
	unsigned int aa:1;
	unsigned int tc:1;
	unsigned int rd:1;

	unsigned int ra:1;
	unsigned int unused:3;
	unsigned int rcode:4;
#else
	unsigned int rd :1;
	unsigned int tc :1;
	unsigned int aa :1;
	unsigned int opcode :4;
	unsigned int qr :1;

	unsigned int rcode :4;
	unsigned int unused :3;
	unsigned int ra :1;
#endif

	unsigned int qdcount :16;
	unsigned int ancount :16;
	unsigned int nscount :16;
	unsigned int arcount :16;
};

enum dns_section {
	DNS_S_QD = 0x01,
#define DNS_S_QUESTION          DNS_S_QD

	DNS_S_AN = 0x02,
#define DNS_S_ANSWER            DNS_S_AN

	DNS_S_NS = 0x04,
#define DNS_S_AUTHORITY         DNS_S_NS

	DNS_S_AR = 0x08,
#define DNS_S_ADDITIONAL        DNS_S_AR

	DNS_S_ALL = 0x0f
};
/* enum dns_section */

enum dns_opcode {
	DNS_OP_QUERY = 0,
	DNS_OP_IQUERY = 1,
	DNS_OP_STATUS = 2,
	DNS_OP_NOTIFY = 4,
	DNS_OP_UPDATE = 5,
};
/* dns_opcode */

enum dns_class {
	DNS_C_IN = 1,

	DNS_C_ANY = 255
};
/* enum dns_class */

struct dns_query {
	char *qname;
	unsigned int qtype :16;
	unsigned int qclass :16;
};

enum dns_type {
	DNS_T_A = 1,
	DNS_T_NS = 2,
	DNS_T_CNAME = 5,
	DNS_T_SOA = 6,
	DNS_T_PTR = 12,
	DNS_T_MX = 15,
	DNS_T_TXT = 16,
	DNS_T_AAAA = 28,
	DNS_T_SRV = 33,
	DNS_T_OPT = 41,
	DNS_T_SSHFP = 44,
	DNS_T_SPF = 99,

	DNS_T_ALL = 255
};
/* enum dns_type */

static const char dns_rcodes[16][16] = {
	[DNS_RC_NOERROR]  = "NOERROR",
	[DNS_RC_FORMERR]  = "FORMERR",
	[DNS_RC_SERVFAIL] = "SERVFAIL",
	[DNS_RC_NXDOMAIN] = "NXDOMAIN",
	[DNS_RC_NOTIMP]   = "NOTIMP",
	[DNS_RC_REFUSED]  = "REFUSED",
	[DNS_RC_YXDOMAIN] = "YXDOMAIN",
	[DNS_RC_YXRRSET]  = "YXRRSET",
	[DNS_RC_NXRRSET]  = "NXRRSET",
	[DNS_RC_NOTAUTH]  = "NOTAUTH",
	[DNS_RC_NOTZONE]  = "NOTZONE",
};

static const char dns_types[7][16] = {
		[DNS_REQUEST_A] = "A request",
		[DNS_REQUEST_PTR] = "PTR request",
		[DNS_REQUEST_MX] = "MX request",
		[DNS_REQUEST_TXT] = "TXT request",
		[DNS_REQUEST_SRV] = "SRV request",
		[DNS_REQUEST_SPF] = "SPF request",
		[DNS_REQUEST_AAA] = "AAA request"
};

/**
 * Convert an UCS4 string to a puny-coded DNS label string suitable
 * when combined with delimiters and other labels for DNS lookup.
 *
 * @param in an UCS4 string to convert
 * @param in_len the length of in.
 * @param out the resulting puny-coded string. The string is not NULL
 * terminated.
 * @param out_len before processing out_len should be the length of
 * the out variable, after processing it will be the length of the out
 * string.
 *
 * @return returns 0 on success, an wind error code otherwise
 */
bool rdns_punycode_label_toascii (const uint32_t *in, size_t in_len, char *out, size_t *out_len);
/**
 * Convert an UTF-8 string to an UCS4 string.
 *
 * @param in an UTF-8 string to convert.
 * @param out the resulting UCS4 string
 * @param out_len before processing out_len should be the length of
 * the out variable, after processing it will be the length of the out
 * string.
 *
 * @return returns 0 on success, an -1 otherwise
 * @ingroup wind
 */

int rdns_utf8_to_ucs4 (const char *in, size_t in_len, uint32_t **out, size_t *out_len);

int rdns_make_client_socket (const char *credits, uint16_t port, int type);

#endif /* DNS_PRIVATE_H_ */
