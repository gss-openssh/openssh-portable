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

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "dh.h"
#include "ssh-gss.h"
#include "monitor_wrap.h"
#include "misc.h"
#include "servconf.h"
#include "digest.h"

extern ServerOptions options;

/* ARGSUSED */
int
kexgss_server_hook(struct ssh *ssh, void *arg, char *myproposal[PROPOSAL_MAX])
{
	char *gss = ssh_gssapi_server_mechanisms();
	int r = kex_prop_update_gss(ssh, gss, myproposal);

	free(gss);
	return r;
}

int
kexgss_server(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	static struct sshbuf *nullkey = NULL;
	struct sshbuf *client_pubkey = NULL, *server_pubkey = NULL;
	struct sshbuf *shared_secret = NULL;
	OM_uint32 maj_status, min_status;
	kex_enc_hash_fn_t *hash_fn = kex_gen_enc_hash_server;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	u_int32_t seqnr;
	u_char msgtype;
	int r;
	
	/*
	 * Some GSSAPI implementations use the input value of ret_flags (an
	 * output variable) as a means of triggering mechanism specific
	 * features. Initializing it to zero avoids inadvertently
	 * activating this non-standard behaviour.
	 */

	OM_uint32 ret_flags = 0;
	gss_buffer_desc gssbuf, mic_tok;
	gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	Gssctxt *ctxt = NULL;
	int type = 0;
	gss_OID oid;

	if (nullkey == NULL && (nullkey = sshbuf_from("", 0)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* Initialise GSSAPI */

	/*
	 * If we're rekeying, privsep means that some of the private structures
	 * in the GSSAPI code are no longer available. This kludges them back
	 * into life
	 */
	if (!ssh_gssapi_oid_table_ok())
		free(ssh_gssapi_server_mechanisms());

	debug2("%s: Identifying %s", __func__, kex->name);
	oid = ssh_gssapi_id_kex(NULL, kex->name, kex->kex_type);
	if (oid == GSS_C_NO_OID) {
		error("Unknown gssapi mechanism");
		return SSH_ERR_GSSAPI_ERROR;
	}

	debug2("%s: Acquiring credentials", __func__);

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_server_ctx(&ctxt, oid)))) {
		error("Unable to acquire credentials for the server");
		return SSH_ERR_GSSAPI_ERROR;
	}

	switch (kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
	case KEX_GSS_GRP16_SHA512:
	case KEX_GSS_GRP18_SHA512:
	case KEX_GSS_C25519_SHA256:
		r = 0;
		break;

	case KEX_GSS_GEX_SHA1:
		if ((r = ssh_packet_read_seqnr(ssh, &msgtype, &seqnr)) == 0 &&
		    msgtype == SSH2_MSG_KEXGSS_GROUPREQ) {
			r = kex_dh_gex_request(KEX_GSS_GEX_SHA1, seqnr, ssh);
		} else {
		    (void) sshpkt_disconnect(ssh,
			"Protocol error: expected packet type %d, got %d",
			SSH2_MSG_KEXGSS_GROUPREQ, msgtype);
		    r = SSH_ERR_PROTOCOL_ERROR;
		}
		hash_fn = kex_gex_enc_hash_server;
		break;

	default:
		r = SSH_ERR_NO_KEX_ALG_MATCH;
		break;
	}
	if (r != 0)
		goto out;

	do {
		debug("Wait SSH2_MSG_GSSAPI_INIT");

		switch(type = ssh_packet_read(ssh)) {
		case SSH2_MSG_KEXGSS_INIT:
			if (client_pubkey != NULL) {
				r = SSH_ERR_PROTOCOL_ERROR;
				goto out;
			}
			if ((r = sshpkt_get_buffer_desc(ssh, &recv_tok)) != 0 ||
			    (r = sshpkt_getb_froms(ssh, &client_pubkey)) != 0)
			    goto out;

			/* Send SSH_MSG_KEXGSS_HOSTKEY here, if we want */
			break;

		case SSH2_MSG_KEXGSS_CONTINUE:
			if (client_pubkey == NULL) {
				r = SSH_ERR_PROTOCOL_ERROR;
				goto out;
			}
			if ((r = sshpkt_get_buffer_desc(ssh, &recv_tok)) != 0)
			    goto out;
			break;

		default:
			(void) sshpkt_disconnect(ssh,
			    "Protocol error: didn't expect packet type %d", type);
			r = SSH_ERR_PROTOCOL_ERROR;
			goto out;
		}

		maj_status = PRIVSEP(ssh_gssapi_accept_ctx(ctxt, &recv_tok,
		    &send_tok, &ret_flags));
		free(recv_tok.value);
		recv_tok.value = NULL;

		if (maj_status != GSS_S_COMPLETE && send_tok.length == 0) {
			error("Zero length token output when incomplete");
			r = SSH_ERR_GSSAPI_ERROR;
			goto out;
		}

		if (maj_status & GSS_S_CONTINUE_NEEDED) {
			debug("Sending GSSAPI_CONTINUE");
			if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value, send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				goto out;
			gss_release_buffer(&min_status, &send_tok);
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	if (GSS_ERROR(maj_status)) {
		if (send_tok.length > 0) {
			if ((r = sshpkt_start(ssh,
				SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
			    (r = sshpkt_put_string(ssh, send_tok.value,
				send_tok.length)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				goto out;
		}
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	if (!(ret_flags & GSS_C_MUTUAL_FLAG)) {
		error("Mutual Authentication flag wasn't set");
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	if (!(ret_flags & GSS_C_INTEG_FLAG)) {
		error("Integrity flag wasn't set");
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	hashlen = sizeof(hash);
	if ((r = hash_fn(ssh, client_pubkey, &server_pubkey, nullkey,
	    &shared_secret, hash, &hashlen)) != 0) {
		error("error deriving DH shared secret");
		goto out;
	}

	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	if (GSS_ERROR(PRIVSEP(ssh_gssapi_sign(ctxt, &gssbuf, &mic_tok)))) {
		error("Couldn't get MIC");
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEXGSS_COMPLETE)) != 0 ||
	    (r = sshpkt_put_stringb(ssh, server_pubkey)) != 0 ||
	    (r = sshpkt_put_string(ssh, mic_tok.value, mic_tok.length)) != 0) {
		gss_release_buffer(&min_status, &mic_tok);
		goto out;
	}
	gss_release_buffer(&min_status, &mic_tok);

	if (send_tok.length != 0) {
		if ((r = sshpkt_put_u8(ssh, 1)) != 0 || /* true */
		    (r = sshpkt_put_string(ssh, send_tok.value,
					   send_tok.length)) != 0)
			goto out;
	} else {
		if ((r = sshpkt_put_u8(ssh, 0)) != 0) /* false */
			goto out;
	}
	if ((r = sshpkt_send(ssh)) != 0)
		goto out;

	if (gss_kex_context == NULL) {
		gss_kex_context = ctxt;
		ctxt = NULL;
	}

	DH_free(kex->dh);
	kex->dh = NULL;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) != 0 ||
	    (r = kex_send_newkeys(ssh)) != 0)
		goto out;

	/*
	 * If this was a rekey, then save out any delegated credentials we just
	 * exchanged.
	 */
	if (options.gss_store_rekey)
		ssh_gssapi_rekey_creds();

 out:
	sshbuf_free(client_pubkey);
	sshbuf_free(shared_secret);
	explicit_bzero(hash, sizeof(hash));
	free(recv_tok.value);
	gss_release_buffer(&min_status, &send_tok);
	ssh_gssapi_delete_ctx(&ctxt);
	return r;
}
#endif /* GSSAPI */
