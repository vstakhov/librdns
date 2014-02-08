/*
 * Copyright (c) 2013-2014, Vsevolod Stakhov
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

#ifndef Rdns_H
#define Rdns_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct rdns_reply;
struct config_file;

typedef void (*dns_callback_type) (struct rdns_reply *reply, void *arg);

enum rdns_request_type {
	DNS_REQUEST_A = 0,
	DNS_REQUEST_PTR,
	DNS_REQUEST_MX,
	DNS_REQUEST_TXT,
	DNS_REQUEST_SRV,
	DNS_REQUEST_SPF,
	DNS_REQUEST_AAA
};

union rdns_reply_element_un {
	struct {
		struct in_addr addr;
	} a;
	struct {
		struct in6_addr addr;
	} aaa;
	struct {
		char *name;
	} ptr;
	struct {
		char *name;
		uint16_t priority;
	} mx;
	struct {
		char *data;
	} txt;
	struct {
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		char *target;
	} srv;
};

struct rdns_reply_entry {
	union rdns_reply_element_un content;
	uint16_t type;
	uint16_t ttl;
	struct rdns_reply_entry *prev, *next;
};


enum dns_rcode {
	DNS_RC_NOERROR	= 0,
	DNS_RC_FORMERR	= 1,
	DNS_RC_SERVFAIL	= 2,
	DNS_RC_NXDOMAIN	= 3,
	DNS_RC_NOTIMP	= 4,
	DNS_RC_REFUSED	= 5,
	DNS_RC_YXDOMAIN	= 6,
	DNS_RC_YXRRSET	= 7,
	DNS_RC_NXRRSET	= 8,
	DNS_RC_NOTAUTH	= 9,
	DNS_RC_NOTZONE	= 10,
};
	
struct rdns_reply {
	struct rdns_request *request;
	enum dns_rcode code;
	struct rdns_reply_entry *entries;
};


/* Rspamd DNS API */

/**
 * Create DNS resolver structure
 */
struct rdns_resolver *rdns_resolver_new (void);

/**
 * Add new DNS server definition to the resolver
 * @param resolver resolver object
 * @param name name of DNS server (should be ipv4 or ipv6 address)
 * @param priority priority (can be 0 for fair round-robin)
 * @return true if a server has been added to resolver
 */
bool rdns_resolver_add_server (struct rdns_resolver *resolver,
		const char *name, int priority);

/**
 * Init DNS resolver
 * @param resolver
 * @return
 */
bool rdns_resolver_init (struct rdns_resolver *resolver);

/**
 * Make a DNS request
 * @param resolver resolver object
 * @param cb callback to call on resolve completing
 * @param ud user data for callback
 * @param timeout timeout in seconds
 * @param repeats how much time to retransmit query
 * @param queries how much RR queries to send
 * @param ... -> queries in format: <query_type>[,type_argument[,type_argument...]]
 * @return TRUE if request was sent.
 */
bool rdns_make_request_full (
		struct rdns_resolver *resolver,
		dns_callback_type cb,
		void *cbdata,
		double timeout,
		unsigned int repeats,
		const char *name,
		unsigned int queries,
		...
		);

/**
 * Get textual presentation of DNS error code
 */
const char *dns_strerror (enum dns_rcode rcode);

/**
 * Get textual presentation of DNS request type
 */
const char *dns_strtype (enum rdns_request_type type);

#endif
