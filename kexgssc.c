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

#include "includes.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <string.h>

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
#include "digest.h"

#include "ssh-gss.h"

static char *
client_mechs(struct kexgss *kexgss)
{
	gss_OID_set mechs = GSS_C_NO_OID_SET;
	gss_OID_set_desc mech1;
	OM_uint32 min_status;

	/*
	 * The first time, we use any available mechanism.  After that, we need
	 * to use only the mechanism we used the first time (or some other
	 * non-GSS KEX).
	 */
	if (kexgss->mech == GSS_C_NO_OID) {
		if (GSS_ERROR(gss_indicate_mechs(&min_status, &mechs)))
			return NULL;
	} else {
		mech1.count = 1;
		mech1.elements = kexgss->mech;
		mechs = &mech1;
	}

	return ssh_gssapi_kex_mechs(mechs, ssh_gssapi_check_mechanism,
	    kexgss->host, kexgss->client, kexgss->name);
}

/* ARGSUSED */
int
kexgss_client_hook(struct ssh *ssh, void *arg, char *myproposal[PROPOSAL_MAX])
{
	char *mechs = client_mechs(&ssh->kex->gss);
	int r = kex_prop_update_gss(ssh, mechs, myproposal);

	free(mechs);
	return r;
}

int
kexgss_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	static const char *gexname = "SSH2_MSG_KEX_DH_GEX_GROUP";
	static const u_int gexrequest = SSH2_MSG_KEXGSS_GROUPREQ;
	static const u_int gexreply = SSH2_MSG_KEXGSS_GROUP;
	struct sshbuf *shared_secret = NULL;
	struct sshbuf *server_dh = NULL;
	struct sshbuf *serverhostkey = NULL;
	static struct sshbuf *nullkey = NULL;
	gss_buffer_desc recv_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	Gssctxt *ctxt;
	OM_uint32 maj_status, min_status, ret_flags;
	u_char hastok;
	u_char *msg;
	int type = 0;
	int first = 1;
	int r;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t hashlen;
	kex_dec_hash_fn_t *hash_fn = kex_gen_dec_hash_client;

	if (nullkey == NULL && (nullkey = sshbuf_from("", 0)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	/* Initialise our GSSAPI world */
	ssh_gssapi_build_ctx(&ctxt);
	if (ssh_gssapi_id_kex(ctxt, kex->name, kex->kex_type) == GSS_C_NO_OID) {
		r = SSH_ERR_NO_KEX_ALG_MATCH;
		goto out;
	}

	if (ssh_gssapi_import_name(ctxt, kex->gss.host)) {
		error("GSS name import failed for: host@%s", kex->gss.host);
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	if (kex->gss.client &&
	    ssh_gssapi_client_identity(ctxt, kex->gss.client, kex->gss.name)) {
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	/*
	 * Generate keys with kex->client_pub set to point to serialized buffer
	 * for sending to the server.
	 */
	switch (kex->kex_type) {
	case KEX_GSS_GRP1_SHA1:
	case KEX_GSS_GRP14_SHA1:
	case KEX_GSS_GRP14_SHA256:
	case KEX_GSS_GRP16_SHA512:
	case KEX_GSS_GRP18_SHA512:
		r = kex_dh_keypair(kex);
		break;

	case KEX_GSS_C25519_SHA256:
		r = kex_c25519_keypair(kex);
		break;

	case KEX_GSS_GEX_SHA1:
		debug("Doing group exchange\n");
		if ((r = sshpkt_start(ssh, gexrequest)) != 0 ||
		    (r = kexgex_client_init(ssh, gexname)) != 0 ||
		    (r = ssh_packet_read_expect(ssh, gexreply)) != 0)
			r = kexgex_client_genkey(ssh);
		hash_fn = kex_gex_dec_hash_client;
		break;

	default:
		r = SSH_ERR_NO_KEX_ALG_MATCH;
	}
	if (r != 0)
		goto out;

	do {
		debug("Calling gss_init_sec_context");

		maj_status = ssh_gssapi_init_ctx(ctxt,
		    kex->gss.deleg_creds, &recv_tok, &send_tok,
		    &ret_flags);
		free(recv_tok.value);
		recv_tok.value = NULL;

		if (GSS_ERROR(maj_status)) {
			if (send_tok.length != 0) {
				/*
				 * Send any error token to the server, though no
				 * such tokens should arise with Kerberos as the
				 * mechanism.
				 */
				if ((r = sshpkt_start(ssh,
					SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
					send_tok.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					goto out;
			}
			error("gss_init_context failed");
			r = SSH_ERR_GSSAPI_ERROR;
			goto out;
		}

		if (maj_status == GSS_S_COMPLETE) {
			/* If mutual state flag is not true, kex fails */
			if (!(ret_flags & GSS_C_MUTUAL_FLAG)) {
				error("Mutual authentication failed");
				r = SSH_ERR_GSSAPI_ERROR;
				goto out;
			}

			/* If integ avail flag is not true kex fails */
			if (!(ret_flags & GSS_C_INTEG_FLAG)) {
				error("Integrity check failed");
				r = SSH_ERR_GSSAPI_ERROR;
				goto out;
			}
		} else if (send_tok.length == 0) {
			error("Not complete, and no token output");
			r = SSH_ERR_GSSAPI_ERROR;
			goto out;
		}

		/*
		 * If we have data to send, then the last message that we
		 * received cannot have been a 'complete'.
		 */
		if (send_tok.length != 0) {
			if (first) {
				if ((r = sshpkt_start(ssh,
					SSH2_MSG_KEXGSS_INIT)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
					send_tok.length)) != 0 ||
				    (r = sshpkt_put_stringb(ssh,
					kex->client_pub)) != 0)
					goto out;
				first = 0;
			} else {
				if ((r = sshpkt_start(ssh,
					SSH2_MSG_KEXGSS_CONTINUE)) != 0 ||
				    (r = sshpkt_put_string(ssh, send_tok.value,
					send_tok.length)) != 0)
					goto out;
			}
			gss_release_buffer(&min_status, &send_tok);
			if ((r = sshpkt_send(ssh)) != 0)
				goto out;

			/* The first reply optionally carries a hostkey. */
			type = ssh_packet_read(ssh);
			if (type == SSH2_MSG_KEXGSS_HOSTKEY) {
				debug("Received KEXGSS_HOSTKEY");
				if ((r = sshpkt_getb_froms(ssh, &serverhostkey)) != 0)
					goto out;
				type = ssh_packet_read(ssh);
			}

			switch (type) {
			case SSH2_MSG_KEXGSS_CONTINUE:
				debug("Received GSSAPI_CONTINUE");
				if (maj_status == GSS_S_COMPLETE) {
					error("GSSAPI Continue received from server when complete");
					r = SSH_ERR_GSSAPI_ERROR;
					goto out;
				}
				if ((r = sshpkt_get_buffer_desc(ssh, &recv_tok)) != 0)
					goto out;
				break;
			case SSH2_MSG_KEXGSS_COMPLETE:
				debug("Received GSSAPI_COMPLETE");
				if ((r = sshpkt_getb_froms(ssh, &server_dh)) != 0 ||
				    (r = sshpkt_get_buffer_desc(ssh, &mic_tok)) != 0 ||
				    (r = sshpkt_get_u8(ssh, &hastok)) != 0)
					goto out;

				/* Is there a token included? */
				if (hastok) {
					if ((r = sshpkt_get_buffer_desc(ssh, &recv_tok)) != 0)
						goto out;
					/* If we're already complete - protocol error */
					if (maj_status == GSS_S_COMPLETE) {
						if ((r = sshpkt_disconnect(ssh,
						    "Protocol error: received token when complete")) == 0)
							r = SSH_ERR_GSSAPI_ERROR;
						goto out;
					}
				} else if (maj_status != GSS_S_COMPLETE) {
					/* No token included */
					if ((r = sshpkt_disconnect(ssh,
					    "Protocol error: did not receive final token")) == 0)
						r = SSH_ERR_GSSAPI_ERROR;
					goto out;
				}
				break;
			case SSH2_MSG_KEXGSS_ERROR:
				debug("Received Error");
				/*
				 * Receive maj, min, msg and lang, ignoring all
				 * but the message
				 */
				if ((r = sshpkt_get_u32(ssh, NULL)) == 0 &&
				    (r = sshpkt_get_u32(ssh, NULL)) == 0 &&
				    (r = sshpkt_get_string(ssh, &msg, NULL)) == 0 &&
				    (r = sshpkt_get_string(ssh, NULL, NULL)) == 0) {
					error("GSSAPI Error: \n%.400s", msg);
					r = SSH_ERR_GSSAPI_ERROR;
				}
				goto out;
			default:
				if ((r = sshpkt_disconnect(ssh,
				    "Protocol error: didn't expect packet type %d", type)) == 0)
					r = SSH_ERR_PROTOCOL_ERROR;
				goto out;
			}
		}
	} while (maj_status & GSS_S_CONTINUE_NEEDED);

	/*
	 * We _must_ have received a COMPLETE message in reply from the
	 * server, which will have set server_dh and mic_tok
	 */
	if (type != SSH2_MSG_KEXGSS_COMPLETE) {
		error("SSH2_MSG_KEXGSS_COMPLETE(%d) expected, got: %d",
		    SSH2_MSG_KEXGSS_COMPLETE, type);
		r = SSH_ERR_PROTOCOL_ERROR;
		goto out;
	}

	hashlen = sizeof(hash);
	if ((r = hash_fn(ssh, server_dh, serverhostkey ? serverhostkey : nullkey,
	    &shared_secret, hash, &hashlen)) != 0) {
		(void) sshpkt_disconnect(ssh, "bad server public key value");
		goto out;
	}

	gssbuf.value = hash;
	gssbuf.length = hashlen;

	/* Verify that the hash matches the MIC we just got. */
	if (GSS_ERROR(ssh_gssapi_checkmic(ctxt, &gssbuf, &mic_tok))) {
		(void) sshpkt_disconnect(ssh,
		    "kexgss message integrity failure");
		r = SSH_ERR_GSSAPI_ERROR;
		goto out;
	}

	/* save session id */
	if (kex->session_id == NULL) {
		kex->session_id_len = hashlen;
		kex->session_id = xmalloc(kex->session_id_len);
		memcpy(kex->session_id, hash, kex->session_id_len);
	}

	if (kex->gss.deleg_creds)
		ssh_gssapi_credentials_updated(ctxt, &kex->gss);

	if (gss_kex_context == NULL) {
		gss_kex_context = ctxt;
		ctxt = NULL;
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0 &&
	    (r = kex_send_newkeys(ssh)) == 0)
		kex_authenticated(ssh);

 out:
	sshbuf_free(serverhostkey);
	sshbuf_free(server_dh);
	free(mic_tok.value);
	free(recv_tok.value);
	gss_release_buffer(&min_status, &send_tok);
	ssh_gssapi_delete_ctx(&ctxt);
	explicit_bzero(hash, sizeof(hash));
	sshbuf_free(shared_secret);
	return r;
}
#endif /* GSSAPI */
