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

struct rdns_curve_entry {
	char *name;
	char pubkey[RDSN_CURVE_PUBKEY_LEN];
	UT_hash_handle hh;
};

struct rdns_curve_ctx {
	struct rdns_curve_entry *entries;
};

struct rdns_curve_ctx*
rdns_curve_ctx_new (void)
{
	struct rdns_curve_ctx *new;

	new = calloc (1, sizeof (struct rdns_curve_ctx));

	return new;
}


void
rdns_curve_ctx_add_key (struct rdns_curve_ctx *ctx,
		const char *name, const char *pubkey)
{
	struct rdns_curve_entry *entry;
	int len;

	len = strlen (pubkey);

	if (len == RDSN_CURVE_PUBKEY_LEN) {
		entry = malloc (sizeof (struct rdns_curve_entry));
		entry->name = strdup (name);
		memcpy (entry->pubkey, pubkey, sizeof (entry->pubkey));
		HASH_ADD_KEYPTR (hh, ctx->entries, entry->name, strlen (entry->name), entry);
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

}
