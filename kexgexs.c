/* $OpenBSD: kexgexs.c,v 1.42 2019/01/23 00:30:41 djm Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
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

#ifdef WITH_OPENSSL


#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <openssl/dh.h>

#include "openbsd-compat/openssl-compat.h"

#include "sshkey.h"
#include "cipher.h"
#include "digest.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh2.h"
#include "compat.h"
#ifdef GSSAPI
#include "ssh-gss.h"
#endif
#include "monitor_wrap.h"
#include "dispatch.h"
#include "ssherr.h"
#include "sshbuf.h"
#include "misc.h"

static int input_kex_dh_gex_init(int, u_int32_t, struct ssh *);

int kex_gex_enc_hash_server(struct ssh *ssh, const struct sshbuf *client_dh,
    struct sshbuf **server_dh, const struct sshbuf *server_host_key_blob,
    struct sshbuf **shared_secret, u_char *hash, size_t *hashlenp)
{
	struct kex *kex = ssh->kex;
	struct sshbuf *buf = NULL;
	struct sshbuf *buf2 = NULL;
	BIGNUM *client_pub = NULL;
	const BIGNUM *server_pub, *dh_p, *dh_g;
	int r;

	*shared_secret = NULL;

	if ((buf = sshbuf_new()) == NULL ||
	    (buf2 = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Encode server public key and skip the length, then decode the client
	 * key.
	 */
	DH_get0_key(kex->dh, &server_pub, NULL);
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);
	if ((r = sshbuf_put_bignum2(buf2, server_pub)) != 0 ||
	    (r = sshbuf_get_u32(buf2, NULL)) != 0 ||
	    (r = sshbuf_put_stringb(buf, client_dh)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &client_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	if ((r = kex_dh_compute_key(kex, client_pub, buf)) != 0)
		goto out;

	/* calc H */
	if ((r = kexgex_hash(
	    kex->hash_alg,
	    kex->client_version,
	    kex->server_version,
	    kex->peer,
	    kex->my,
	    server_host_key_blob,
	    kex->min, kex->nbits, kex->max,
	    dh_p, dh_g,
	    client_pub,
	    server_pub,
	    sshbuf_ptr(buf), sshbuf_len(buf),
	    hash, hashlenp)) != 0)
		goto out;

	*shared_secret = buf;
	*server_dh = buf2;
	buf = buf2 = NULL;

 out:
	BN_clear_free(client_pub);
	DH_free(kex->dh);
	kex->dh = NULL;
	free(buf);
	free(buf2);
	return r;
}

int
kexgex_server(struct ssh *ssh)
{
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_REQUEST,
	    &kex_dh_gex_request);
	debug("expecting SSH2_MSG_KEX_DH_GEX_REQUEST");
	return 0;
}

int
kex_dh_gex_request(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	int r;
	u_int min = 0, max = 0, nbits = 0;
	const BIGNUM *dh_p, *dh_g;

	switch (type) {
	case SSH2_MSG_KEX_DH_GEX_REQUEST:
		debug("SSH2_MSG_KEX_DH_GEX_REQUEST received");
		break;
#ifdef GSSAPI
	case KEX_GSS_GEX_SHA1:
		debug("SSH2_MSG_KEXGSS_GROUPREQ received");
		break;
#endif
	default:
		return SSH_ERR_NO_KEX_ALG_MATCH;
	}

	if ((r = sshpkt_get_u32(ssh, &min)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &nbits)) != 0 ||
	    (r = sshpkt_get_u32(ssh, &max)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	kex->nbits = nbits;
	kex->min = min;
	kex->max = max;
	min = MAXIMUM(DH_GRP_MIN, min);
	max = MINIMUM(DH_GRP_MAX, max);
	nbits = MAXIMUM(DH_GRP_MIN, nbits);
	nbits = MINIMUM(DH_GRP_MAX, nbits);

	if (kex->max < kex->min || kex->nbits < kex->min ||
	    kex->max < kex->nbits || kex->max < DH_GRP_MIN) {
		r = SSH_ERR_DH_GEX_OUT_OF_RANGE;
		goto out;
	}

	/* Contact privileged parent */
	kex->dh = PRIVSEP(choose_dh(min, nbits, max));
	if (kex->dh == NULL) {
		sshpkt_disconnect(ssh, "no matching DH grp found");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	DH_get0_pqg(kex->dh, &dh_p, NULL, &dh_g);

	switch (type) {
	case SSH2_MSG_KEX_DH_GEX_REQUEST:
		debug("SSH2_MSG_KEX_DH_GEX_GROUP sent");
		r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_GROUP);
		break;
#ifdef GSSAPI
	case KEX_GSS_GEX_SHA1:
		debug("SSH2_MSG_KEXGSS_GROUP sent");
		r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_GROUP);
		break;
#endif
	}

	if (r != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_p)) != 0 ||
	    (r = sshpkt_put_bignum2(ssh, dh_g)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	/* Compute our exchange value in parallel with the client */
	if ((r = dh_gen_key(kex->dh, kex->we_need * 8)) != 0)
		goto out;

	switch (type) {
	case SSH2_MSG_KEX_DH_GEX_REQUEST:
	    debug("expecting SSH2_MSG_KEX_DH_GEX_INIT");
	    ssh_dispatch_set(ssh, SSH2_MSG_KEX_DH_GEX_INIT, &input_kex_dh_gex_init);
	    break;
#ifdef GSSAPI
	case KEX_GSS_GEX_SHA1:
	    break;
#endif
	}
	r = 0;
 out:
	return r;
}

static int
input_kex_dh_gex_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshbuf *dh_client_blob = NULL;
	struct sshbuf *dh_server_blob = NULL;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_host_key_blob = NULL;
	struct sshkey *server_host_public, *server_host_private;
	u_char *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, hashlen;
	int r;

	if ((r = kex_load_hostkey(ssh, &server_host_private,
	    &server_host_public)) != 0)
		goto out;

	/* key, cert */
	if ((r = sshpkt_getb_froms(ssh, &dh_client_blob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
	if ((server_host_key_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshkey_putb(server_host_public, server_host_key_blob)) != 0)
		goto out;

	/* calc H */
	hashlen = sizeof(hash);
	if ((r = kex_gex_enc_hash_server(ssh, dh_client_blob, &dh_server_blob,
	    server_host_key_blob, &shared_secret, hash, &hashlen)) != 0)
		goto out;

	/* sign H */
	if ((r = kex->sign(ssh, server_host_private, server_host_public,
	    &signature, &slen, hash, hashlen, kex->hostkey_alg)) < 0)
		goto out;

	/* send server hostkey, DH pubkey 'f' and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_DH_GEX_REPLY)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_host_key_blob)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, dh_server_blob)) != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
		r = kex_send_newkeys(ssh);
 out:
	explicit_bzero(hash, sizeof(hash));
	DH_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(dh_client_blob);
	sshbuf_free(dh_server_blob);
	sshbuf_free(shared_secret);
	sshbuf_free(server_host_key_blob);
	free(signature);
	return r;
}
#endif /* WITH_OPENSSL */
