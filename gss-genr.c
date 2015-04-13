/* $OpenBSD: gss-genr.c,v 1.26 2018/07/10 09:13:30 djm Exp $ */

/*
 * Copyright (c) 2001-2009 Simon Wilkinson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR `AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef GSSAPI

#include <sys/types.h>

#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "xmalloc.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "log.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "myproposal.h"
#include <openssl/evp.h>

#include "ssh-gss.h"
#include "packet.h"
#include "digest.h"

#define SSH_MD5_SIZE 16	/* For mech strings */

extern u_char *session_id2;
extern u_int session_id2_len;

typedef struct {
	char *encoded;
	gss_OID oid;
} ssh_gss_kex_mapping;

/*
 * XXX - It would be nice to find a more elegant way of handling the
 * XXX   passing of the key exchange context to the userauth routines
 */

Gssctxt *gss_kex_context = NULL;

static ssh_gss_kex_mapping *gss_enc2oid = NULL;

static int log_gssapi_errors = 0;

void
ssh_log_gssapi_errors(int on)
{
	log_gssapi_errors = on;
}

int 
ssh_gssapi_oid_table_ok(void)
{
	return (gss_enc2oid != NULL);
}

char *
ssh_gssapi_kex_mechs(gss_OID_set gss_supported, ssh_gssapi_check_fn *check,
    const char *host, const char *client, gss_name_t client_name)
{
	static char *groups[] = { KEX_SERVER_GSSKEX };
	size_t g;
	struct sshbuf *buf;
	int r;
	size_t i;
	size_t oidpos;
	size_t enclen;
	size_t mlen;
	char *mechs = NULL, *encoded;
	u_char digest[SSH_MD5_SIZE];
	char deroid[2];
	struct ssh_digest_ctx *md;

	if (gss_enc2oid != NULL) {
		for (i = 0; gss_enc2oid[i].encoded != NULL; i++)
			free(gss_enc2oid[i].encoded);
		free(gss_enc2oid);
	}

	gss_enc2oid = xmalloc(sizeof(ssh_gss_kex_mapping) *
	    (gss_supported->count + 1));

	if ((md = ssh_digest_start(SSH_DIGEST_MD5)) == NULL)
		fatal("%s: ssh_digest_start(MD5) failed", __func__);
	for (i = oidpos = 0; i < gss_supported->count; i++) {
		if (gss_supported->elements[i].length < 128 &&
		    (*check)(NULL, &(gss_supported->elements[i]),
			host, client, client_name)) {

			deroid[0] = SSH_GSS_OIDTYPE;
			deroid[1] = gss_supported->elements[i].length;

			if (ssh_digest_update(md, deroid, 2) != 0 ||
			    ssh_digest_update(md,
				gss_supported->elements[i].elements,
				gss_supported->elements[i].length) != 0 ||
			    ssh_digest_final(md, digest, SSH_MD5_SIZE) != 0)
			fatal("%s: ssh_digest_final(MD5) failed", __func__);

			encoded = xmalloc(SSH_MD5_SIZE * 2);
			/* Constant length of a base64 encoded MD5 digest */
			enclen = __b64_ntop(digest, SSH_MD5_SIZE,
			    encoded, SSH_MD5_SIZE * 2);

			gss_enc2oid[oidpos].oid = &(gss_supported->elements[i]);
			gss_enc2oid[oidpos].encoded = encoded;
			oidpos++;
		}
	}
	ssh_digest_free(md);

	gss_enc2oid[oidpos].oid = NULL;
	gss_enc2oid[oidpos].encoded = NULL;

	if ((buf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	/* Order by the group, not the GSS oid */
	for (g = 0; g < sizeof(groups)/sizeof(groups[0]); ++g) {
		for (i = 0; i < oidpos; i++) {
			if ((sshbuf_len(buf) != 0 &&
			     (r = sshbuf_put_u8(buf, ',')) != 0) ||
			     (r = sshbuf_put(buf, groups[g],
				 strlen(groups[g]))) != 0 ||
			     (r = sshbuf_put(buf, gss_enc2oid[i].encoded,
				 enclen)) != 0) /* enclen computed above */
				fatal("%s: buffer error: %s", __func__,
				    ssh_err(r));
		}
	}

	if ((r = sshbuf_put_u8(buf, '\0')) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));

	mlen = sshbuf_len(buf);
	if (mlen > 0) {
	    mechs = xmalloc(mlen);
	    if ((r = sshbuf_get(buf, mechs, mlen)) != 0)
		    fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	sshbuf_free(buf);

	return (mechs);
}

gss_OID
ssh_gssapi_id_kex(Gssctxt *ctx, char *name, int kex_type) {
	int i = 0;

	switch (kex_type) {
	case KEX_GSS_GRP1_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GRP1_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GRP1_SHA1_ID) - 1;
		break;

	case KEX_GSS_GRP14_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GRP14_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GRP14_SHA1_ID) - 1;
		break;

	case KEX_GSS_GEX_SHA1:
		if (strlen(name) < sizeof(KEX_GSS_GEX_SHA1_ID))
			return GSS_C_NO_OID;
		name += sizeof(KEX_GSS_GEX_SHA1_ID) - 1;
		break;

	default:
		return GSS_C_NO_OID;
	}

	while (gss_enc2oid[i].encoded != NULL &&
	    strcmp(name, gss_enc2oid[i].encoded) != 0)
		i++;

	if (gss_enc2oid[i].oid != NULL && ctx != NULL)
		ssh_gssapi_set_oid(ctx, gss_enc2oid[i].oid);

	return gss_enc2oid[i].oid;
}

/* sshbuf_get_string for gss_buffer_desc */
int
ssh_gssapi_get_buffer_desc(struct sshbuf *b, gss_buffer_desc *g)
{
	int r;
	u_char *p;
	size_t len;

	if ((r = sshbuf_get_string(b, &p, &len)) != 0)
		return r;
	g->value = p;
	g->length = len;
	return 0;
}

/* sshpkt_get_string for gss_buffer_desc */
int
sshpkt_get_buffer_desc(struct ssh *ssh, gss_buffer_desc *g)
{
	int r;
	u_char *p;
	size_t len;

	if ((r = sshpkt_get_string(ssh, &p, &len)) != 0)
		return r;
	g->value = p;
	g->length = len;
	return 0;
}

/* Check that the OID in a data stream matches that in the context */
int
ssh_gssapi_check_oid(Gssctxt *ctx, void *data, size_t len)
{
	return (ctx != NULL && ctx->oid != GSS_C_NO_OID &&
	    ctx->oid->length == len &&
	    memcmp(ctx->oid->elements, data, len) == 0);
}

/* Set the contexts OID from a data stream */
void
ssh_gssapi_set_oid_data(Gssctxt *ctx, void *data, size_t len)
{
	if (ctx->oid != GSS_C_NO_OID) {
		free(ctx->oid->elements);
		free(ctx->oid);
	}
	ctx->oid = xcalloc(1, sizeof(gss_OID_desc));
	ctx->oid->length = len;
	ctx->oid->elements = xmalloc(len);
	memcpy(ctx->oid->elements, data, len);
}

/* Set the contexts OID */
void
ssh_gssapi_set_oid(Gssctxt *ctx, gss_OID oid)
{
	ssh_gssapi_set_oid_data(ctx, oid->elements, oid->length);
}

/* All this effort to report an error ... */
void
ssh_gssapi_error(Gssctxt *ctxt)
{
	char *s;

	s = ssh_gssapi_last_error(ctxt, NULL, NULL);
	if (log_gssapi_errors)
		logit("%s", s);
	else
		debug("%s", s);
	free(s);
}

char *
ssh_gssapi_last_error(Gssctxt *ctxt, OM_uint32 *major_status,
    OM_uint32 *minor_status)
{
	OM_uint32 lmin;
	gss_buffer_desc msg = GSS_C_EMPTY_BUFFER;
	OM_uint32 ctx;
	struct sshbuf *b;
	char *ret;
	int r;

	if ((b = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", __func__);

	if (major_status != NULL)
		*major_status = ctxt->major;
	if (minor_status != NULL)
		*minor_status = ctxt->minor;

	ctx = 0;
	/* The GSSAPI error */
	do {
		gss_display_status(&lmin, ctxt->major,
		    GSS_C_GSS_CODE, ctxt->oid, &ctx, &msg);

		if ((sshbuf_len(b) > 0 && (r = sshbuf_put(b, ": ", 2) != 0)) ||
		    (r = sshbuf_put(b, msg.value, msg.length)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	/* The mechanism specific error */
	do {
		gss_display_status(&lmin, ctxt->minor,
		    GSS_C_MECH_CODE, ctxt->oid, &ctx, &msg);

		if ((sshbuf_len(b) > 0 && (r = sshbuf_put(b, ": ", 2) != 0)) ||
		    (r = sshbuf_put(b, msg.value, msg.length)) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));

		gss_release_buffer(&lmin, &msg);
	} while (ctx != 0);

	if ((r = sshbuf_put_u8(b, '\n')) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
	ret = xstrdup((const char *)sshbuf_ptr(b));
	sshbuf_free(b);
	return (ret);
}

/*
 * Initialise our GSSAPI context. We use this opaque structure to contain all
 * of the data which both the client and server need to persist across
 * {accept,init}_sec_context calls, so that when we do it from the userauth
 * stuff life is a little easier
 */
void
ssh_gssapi_build_ctx(Gssctxt **ctx)
{
	*ctx = xcalloc(1, sizeof (Gssctxt));
	(*ctx)->context = GSS_C_NO_CONTEXT;
	(*ctx)->name = GSS_C_NO_NAME;
	(*ctx)->oid = GSS_C_NO_OID;
	(*ctx)->creds = GSS_C_NO_CREDENTIAL;
	(*ctx)->client = GSS_C_NO_NAME;
	(*ctx)->client_creds = GSS_C_NO_CREDENTIAL;
}

/* Delete our context, providing it has been built correctly */
void
ssh_gssapi_delete_ctx(Gssctxt **ctx)
{
	OM_uint32 ms;

	if ((*ctx) == NULL)
		return;
	if ((*ctx)->context != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&ms, &(*ctx)->context, GSS_C_NO_BUFFER);
	if ((*ctx)->name != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->name);
	if ((*ctx)->oid != GSS_C_NO_OID) {
		free((*ctx)->oid->elements);
		free((*ctx)->oid);
		(*ctx)->oid = GSS_C_NO_OID;
	}
	if ((*ctx)->creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->creds);
	if ((*ctx)->client != GSS_C_NO_NAME)
		gss_release_name(&ms, &(*ctx)->client);
	if ((*ctx)->client_creds != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&ms, &(*ctx)->client_creds);

	free(*ctx);
	*ctx = NULL;
}

/*
 * Wrapper to init_sec_context
 * Requires that the context contains:
 *	oid
 *	server name (from ssh_gssapi_import_name)
 */
OM_uint32
ssh_gssapi_init_ctx(Gssctxt *ctx, char *deleg_creds, gss_buffer_desc *recv_tok,
    gss_buffer_desc* send_tok, OM_uint32 *flags)
{
	int deleg_flag = 0;

	if (deleg_creds) {
		deleg_flag = GSS_C_DELEG_FLAG;
		debug("Delegating credentials");
	}

	ctx->major = gss_init_sec_context(&ctx->minor,
	    ctx->client_creds, &ctx->context, ctx->name, ctx->oid,
	    GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | deleg_flag,
	    0, NULL, recv_tok, NULL, send_tok, flags, NULL);

	if (GSS_ERROR(ctx->major))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

/* Create a service name for the given host */
OM_uint32
ssh_gssapi_import_name(Gssctxt *ctx, const char *host)
{
	gss_buffer_desc gssbuf;
	char *val;

	xasprintf(&val, "host@%s", host);
	gssbuf.value = val;
	gssbuf.length = strlen(gssbuf.value);

	if ((ctx->major = gss_import_name(&ctx->minor,
	    &gssbuf, GSS_C_NT_HOSTBASED_SERVICE, &ctx->name)))
		ssh_gssapi_error(ctx);

	free(gssbuf.value);
	return (ctx->major);
}

OM_uint32
ssh_gssapi_client_identity(Gssctxt *ctx, const char *client, gss_name_t name)
{
	OM_uint32 status;
	gss_OID_set_desc mechs;
	gss_name_t newname = GSS_C_NO_NAME;

	if (client != NULL && name == GSS_C_NO_NAME) {
	    gss_buffer_desc gssbuf;

	    gssbuf.value = (void *) client;
	    gssbuf.length = strlen(gssbuf.value);
	    ctx->major = gss_import_name(&ctx->minor, &gssbuf,
		GSS_C_NT_USER_NAME, &newname);
	    name = newname;
	}

	mechs.count = 1;
	mechs.elements = ctx->oid;
	if (!ctx->major)
		ctx->major = gss_acquire_cred(&ctx->minor, name, 0, &mechs,
		    GSS_C_INITIATE, &ctx->client_creds, NULL, NULL);

	if (newname != GSS_C_NO_NAME)
	    (void) gss_release_name(&status, &newname);

	if (ctx->major)
		ssh_gssapi_error(ctx);

	return(ctx->major);
}

OM_uint32
ssh_gssapi_sign(Gssctxt *ctx, gss_buffer_t buffer, gss_buffer_t hash)
{
	if (ctx == NULL) 
		return -1;

	if ((ctx->major = gss_get_mic(&ctx->minor, ctx->context,
	    GSS_C_QOP_DEFAULT, buffer, hash)))
		ssh_gssapi_error(ctx);

	return (ctx->major);
}

/* Priviledged when used by server */
OM_uint32
ssh_gssapi_checkmic(Gssctxt *ctx, gss_buffer_t gssbuf, gss_buffer_t gssmic)
{
	if (ctx == NULL)
		return -1;

	ctx->major = gss_verify_mic(&ctx->minor, ctx->context,
	    gssbuf, gssmic, NULL);

	return (ctx->major);
}

void
ssh_gssapi_buildmic(struct sshbuf *b, const char *user, const char *service,
    const char *context)
{
	int r;

	sshbuf_reset(b);
	if ((r = sshbuf_put_string(b, session_id2, session_id2_len)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, user)) != 0 ||
	    (r = sshbuf_put_cstring(b, service)) != 0 ||
	    (r = sshbuf_put_cstring(b, context)) != 0)
		fatal("%s: buffer error: %s", __func__, ssh_err(r));
}

int
ssh_gssapi_check_mechanism(Gssctxt **ctx, gss_OID oid, const char *host, 
    const char *client, gss_name_t name)
{
	gss_buffer_desc token = GSS_C_EMPTY_BUFFER;
	OM_uint32 major, minor;
	gss_OID_desc spnego_oid = {6, (void *)"\x2B\x06\x01\x05\x05\x02"};
	Gssctxt *intctx = NULL;

	if (ctx == NULL)
		ctx = &intctx;

	/* RFC 4462 says we MUST NOT do SPNEGO */
	if (oid->length == spnego_oid.length && 
	    (memcmp(oid->elements, spnego_oid.elements, oid->length) == 0))
		return 0; /* false */

	ssh_gssapi_build_ctx(ctx);
	ssh_gssapi_set_oid(*ctx, oid);
	major = ssh_gssapi_import_name(*ctx, host);

	if (!GSS_ERROR(major) &&
	    (client != NULL || name != GSS_C_NO_NAME))
		major = ssh_gssapi_client_identity(*ctx, client, name);

	if (!GSS_ERROR(major)) {
		major = ssh_gssapi_init_ctx(*ctx, 0, GSS_C_NO_BUFFER, &token, 
		    NULL);
		gss_release_buffer(&minor, &token);
		if ((*ctx)->context != GSS_C_NO_CONTEXT)
			gss_delete_sec_context(&minor, &(*ctx)->context,
			    GSS_C_NO_BUFFER);
	}

	if (GSS_ERROR(major) || intctx != NULL) 
		ssh_gssapi_delete_ctx(ctx);

	return (!GSS_ERROR(major));
}

int
ssh_gssapi_credentials_updated(Gssctxt *ctxt, struct kexgss *kexgss)
{
	static time_t last_call = 0;
	gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
	OM_uint32 lifetime;
	OM_uint32 major, minor;
	time_t now = time(NULL);
	gss_OID_set_desc mechs;

	if (ctxt) {
		gss_name_t *nameout = NULL;
		gss_OID *mechout = NULL;

		debug("Rekey has happened - updating saved versions");

		last_call = now;

		/*
		 * If we can't figure out when our current credentials expire,
		 * rekey once we have credentials that we *can* determine to
		 * expire more than an hour from now.
		 */
		kexgss->tkt_expiration = kexgss->tgt_expiration = now + 3600;

		/*
		 * Even if our TGT is not newer than before, if our service
		 * ticket expiration changes to a later time, we rekey.  We
		 * hope that delegated credentials don't expire sooner than
		 * the either service ticket or the original TGT, but there's
		 * no way to know.  This works in practice.
		 */
		if (kexgss->name == GSS_C_NO_NAME)
			nameout = &kexgss->name;
		if (kexgss->mech == GSS_C_NO_OID)
			mechout = &kexgss->mech;
		major = gss_inquire_context(&minor, ctxt->context,
		    nameout, NULL, &lifetime, mechout, NULL, NULL, NULL);
		if (GSS_ERROR(major))
			return 0;
		if (lifetime != GSS_C_INDEFINITE)
			kexgss->tkt_expiration = now + lifetime;

		/*
		 * Save expiration of corresponding client credential. We rekey
		 * and delegate a new credential as soon as a credential with a
		 * later expiration time is obtained.
		 *
		 * Note, gss_acquire_cred() need not and often does not return
		 * a usable lifetime, because the processing necessary for that
		 * is "deferred".  So we don't even ask.  Instead, we next call
		 * gss_inquire_cred_by_mech(), which does any "deferred" work
		 * and returns the relevant lifetime.
		 */
		mechs.count = 1;
		mechs.elements = kexgss->mech;
		major = gss_acquire_cred(&minor, kexgss->name,
		    GSS_C_INDEFINITE, &mechs, GSS_C_INITIATE, &cred,
		    NULL, NULL);
		if (GSS_ERROR(major))
			return 0;
		major = gss_inquire_cred_by_mech(&minor, cred, kexgss->mech,
		    NULL, &lifetime, NULL, NULL);
		gss_release_cred(&minor, &cred);
		if (lifetime != GSS_C_INDEFINITE)
			kexgss->tgt_expiration = now + lifetime;

		return 0;
	}

#define LIFETIME_QUANTUM 10

	if (now - last_call < LIFETIME_QUANTUM)
		return 0;
	last_call = now;

	/*
	 * We don't want to bother *if* our current cred's lifetime is no use.
	 *
	 * If we failed to save the mech (and name) before, just go with
	 * defaults until we do.
	 */
	if (kexgss->mech != GSS_C_NO_OID &&
	    kexgss->name != GSS_C_NO_NAME) {
	    mechs.count = 1;
	    mechs.elements = kexgss->mech;
	    major = gss_acquire_cred(&minor, kexgss->name, GSS_C_INDEFINITE,
		&mechs, GSS_C_INITIATE, &cred, NULL, NULL);
	    if (GSS_ERROR(major))
		    return 0;
	    major = gss_inquire_cred_by_mech(&minor, cred, kexgss->mech, NULL,
		&lifetime, NULL, NULL);
	} else {
	    major = gss_acquire_cred(&minor, GSS_C_NO_NAME, GSS_C_INDEFINITE,
		GSS_C_NO_OID_SET, GSS_C_INITIATE, &cred, NULL, NULL);
	    if (GSS_ERROR(major))
		    return 0;
	    /*
	     * XXX: With gss_inquire_cred(), some Heimdal versions return
	     * success and a lifetime of 0 for expired credentials, but that's
	     * just fine, we don't use anything with a lifetime shorter than
	     * LIFETIME_QUANTUM.  Note, this is not an issue with
	     * gss_inquire_cred_by_mech().
	     */
	    major = gss_inquire_cred(&minor, GSS_C_NO_CREDENTIAL,
		NULL, &lifetime, NULL, NULL);
	}
	gss_release_cred(&minor, &cred);
	if (GSS_ERROR(major))
		return 0;

	/* Redelegate any updated TGT. */
	if (lifetime != GSS_C_INDEFINITE && kexgss->tgt_expiration &&
	    now + lifetime > kexgss->tgt_expiration + LIFETIME_QUANTUM)
		return 1;

	/*
	 * If we're near (within LIFETIME_QUANTUM) of the service ticket
	 * expiration time, rekey.
	 */
	if (kexgss->tkt_expiration &&
	    now > kexgss->tkt_expiration - LIFETIME_QUANTUM)
		return 1;

	return 0;
}

void
ssh_free_kexgss(struct kexgss *kexgss)
{
	OM_uint32 dummy;
	gss_release_name(&dummy, &kexgss->name);
}

#endif /* GSSAPI */
