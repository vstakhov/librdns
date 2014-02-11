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

#include "rdns.h"
#include "dns_private.h"
#include "rdns_curve.h"
#include "ottery.h"

#ifdef HAVE_SODIUM
#include <sodium.h>

ssize_t rdns_curve_send (struct rdns_request *req, void *plugin_data);
ssize_t rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len,
		void *plugin_data, struct rdns_request **req_out);
void rdns_curve_finish_request (struct rdns_request *req, void *plugin_data);
#endif

struct rdns_curve_entry {
	char *name;
#ifdef HAVE_SODIUM
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
#endif
	UT_hash_handle hh;
};

struct rdns_curve_nm_entry {
	unsigned char k[crypto_box_BEFORENMBYTES];
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *prev, *next;
};

struct rdns_curve_client_key {
#ifdef HAVE_SODIUM
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	struct rdns_curve_nm_entry *nms;
#endif
	uint64_t counter;
	unsigned int uses;
	unsigned int ref;
};

struct rdns_curve_request {
	struct rdns_request *req;
	struct rdns_curve_client_key *key;
	struct rdns_curve_entry *entry;
	struct rdns_curve_nm_entry *nm;
#ifdef HAVE_SODIUM
	unsigned char nonce[crypto_box_NONCEBYTES];
#endif
	UT_hash_handle hh;
};

struct rdns_curve_ctx {
	struct rdns_curve_entry *entries;
	struct rdns_curve_client_key *cur_key;
	struct rdns_curve_request *requests;
};

static struct rdns_curve_client_key *
rdns_curve_client_key_new (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_client_key *new;
	struct rdns_curve_nm_entry *nm;
	struct rdns_curve_entry *entry, *tmp;

	new = calloc (1, sizeof (struct rdns_curve_client_key));
#ifdef HAVE_SODIUM
	crypto_box_keypair (new->pk, new->sk);

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		nm = calloc (1, sizeof (struct rdns_curve_nm_entry));
		nm->entry = entry;
		crypto_box_beforenm (nm->k, entry->pk, new->sk);
		DL_APPEND (new->nms, nm);
	}

	new->counter = ottery_rand_uint64 ();
#endif

	return new;
}

static struct rdns_curve_nm_entry *
rdns_curve_find_nm (struct rdns_curve_client_key *key, struct rdns_curve_entry *entry)
{
	struct rdns_curve_nm_entry *nm;

	DL_FOREACH (key->nms, nm) {
		if (nm->entry == entry) {
			return nm;
		}
	}

	return NULL;
}

static struct rdns_curve_client_key *
rdns_curve_client_key_ref (struct rdns_curve_client_key *key)
{
	key->ref ++;
	return key;
}

static void
rdns_curve_client_key_unref (struct rdns_curve_client_key *key)
{
	if (--key->ref == 0) {
		free (key);
	}
}

struct rdns_curve_ctx*
rdns_curve_ctx_new (void)
{
	struct rdns_curve_ctx *new;

	new = calloc (1, sizeof (struct rdns_curve_ctx));

	return new;
}

void
rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const unsigned char *pubkey)
{
	struct rdns_curve_entry *entry;
	int len;
	bool success = true;
	unsigned char *pk, *sk;

	entry = malloc (sizeof (struct rdns_curve_entry));
	if (entry != NULL) {
		entry->name = strdup (name);
		if (entry->name == NULL) {
			success = false;
		}
		memcpy (entry->pk, pubkey, sizeof (entry->pk));
		if (success) {
			HASH_ADD_KEYPTR (hh, ctx->entries, entry->name, strlen (entry->name), entry);
		}
	}
}

void rdns_curve_ctx_destroy (struct rdns_curve_ctx *ctx)
{
	struct rdns_curve_entry *entry, *tmp;

	HASH_ITER (hh, ctx->entries, entry, tmp) {
		free (entry->name);
		free (entry);
	}

	free (ctx);
}

void
rdns_curve_register_plugin (struct rdns_resolver *resolver,
		struct rdns_curve_ctx *ctx)
{
#ifdef HAVE_SODIUM
	struct rdns_plugin *plugin;

	plugin = calloc (1, sizeof (struct rdns_plugin));
	if (plugin != NULL) {
		plugin->data = ctx;
		plugin->type = RDNS_PLUGIN_NETWORK;
		plugin->cb.network_plugin.send_cb = rdns_curve_send;
		plugin->cb.network_plugin.recv_cb = rdns_curve_recv;
		plugin->cb.network_plugin.finish_cb = rdns_curve_finish_request;
		sodium_init ();
		ctx->cur_key = rdns_curve_client_key_ref (rdns_curve_client_key_new (ctx));
		rdns_resolver_register_plugin (resolver, plugin);
	}
#endif
}

#ifdef HAVE_SODIUM
ssize_t
rdns_curve_send (struct rdns_request *req, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_entry *entry;
	struct iovec iov[4];
	unsigned char *m, *c;
	static const char qmagic[] = "Q6fnvWj8";
	struct rdns_curve_request *creq;
	struct rdns_curve_nm_entry *nm;
	ssize_t ret;

	/* Check for key */
	HASH_FIND_PTR (ctx->entries, req->io->srv->name, entry);
	if (entry != NULL) {
		nm = rdns_curve_find_nm (ctx->cur_key, entry);
		creq = malloc (sizeof (struct rdns_curve_request));
		if (creq == NULL) {
			return -1;
		}

		m = malloc (req->pos + crypto_box_ZEROBYTES);
		if (m == NULL) {
			return -1;
		}

		/* Ottery is faster than sodium native PRG that uses /dev/random only */
		memcpy (creq->nonce, &ctx->cur_key->counter, sizeof (uint64_t));
		ottery_rand_bytes (creq->nonce + sizeof (uint64_t), 12 - sizeof (uint64_t));

		sodium_memzero (creq->nonce + 12, crypto_box_NONCEBYTES - 12);
		sodium_memzero (m, crypto_box_ZEROBYTES);
		memcpy (m + crypto_box_ZEROBYTES, req->packet, req->pos);
		c = malloc (req->pos + crypto_box_ZEROBYTES);
		if (c == NULL) {
			free (m);
			return -1;
		}
		if (crypto_box_afternm (c, m, req->pos + crypto_box_ZEROBYTES,
				creq->nonce, nm->k) == -1) {
			free (c);
			free (m);
			return -1;
		}
		free (m);

		creq->key = rdns_curve_client_key_ref (ctx->cur_key);
		creq->entry = entry;
		creq->req = req;
		creq->nm = nm;
		HASH_ADD_KEYPTR (hh, ctx->requests, creq->nonce, 12, creq);
		req->plugin_data = creq;
		ctx->cur_key->counter ++;
		ctx->cur_key->uses ++;

		/* Now form a dnscurve packet */
		iov[0].iov_base = (void *)qmagic;
		iov[0].iov_len = sizeof (qmagic) - 1;
		iov[1].iov_base = entry->pk;
		iov[1].iov_len = sizeof (entry->pk);
		iov[2].iov_base = creq->nonce;
		iov[2].iov_len = 12;
		iov[3].iov_base = c;
		iov[3].iov_len = req->pos + crypto_box_ZEROBYTES;

		ret = writev (req->io->sock, iov, sizeof (iov) / sizeof (iov[0]));
		free (c);
	}
	else {
		ret = write (req->io->sock, req->packet, req->pos);
		req->plugin_data = NULL;
	}

	return ret;
}

ssize_t
rdns_curve_recv (struct rdns_io_channel *ioc, void *buf, size_t len, void *plugin_data,
		struct rdns_request **req_out)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	ssize_t ret, boxlen;
	static const char rmagic[] = "R6fnvWJ8";
	unsigned char *p, *box;
	unsigned char enonce[crypto_box_NONCEBYTES];
	struct rdns_curve_request *creq;

	ret = read (ioc->sock, buf, len);

	if (ret <= 0 || ret < 64) {
		/* Definitely not a DNSCurve packet */
		return ret;
	}

	if (memcmp (buf, rmagic, sizeof (rmagic)) == 0) {
		/* Likely DNSCurve packet */
		p = ((unsigned char *)buf) + 8;
		HASH_FIND (hh, ctx->requests, p, 12, creq);
		if (creq == NULL) {
			return ret;
		}
		memcpy (enonce, p, crypto_box_NONCEBYTES);
		p += crypto_box_NONCEBYTES;
		boxlen = ret - crypto_box_NONCEBYTES - sizeof (rmagic);
		if (boxlen < 0) {
			return ret;
		}
		box = malloc (boxlen);

		if (crypto_box_open_afternm (box, p, boxlen, enonce, creq->nm->k) != -1) {
			memcpy (buf, box, boxlen - crypto_box_ZEROBYTES);
			ret = boxlen - crypto_box_ZEROBYTES;
			*req_out = creq->req;
		}
		free (box);
	}

	return ret;
}

void
rdns_curve_finish_request (struct rdns_request *req, void *plugin_data)
{
	struct rdns_curve_ctx *ctx = (struct rdns_curve_ctx *)plugin_data;
	struct rdns_curve_request *creq = req->plugin_data;

	if (creq != NULL) {
		rdns_curve_client_key_unref (creq->key);
		HASH_DELETE (hh, ctx->requests, creq);
	}
}

#endif
