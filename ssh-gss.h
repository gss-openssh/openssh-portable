/* $OpenBSD: ssh-gss.h,v 1.14 2018/07/10 09:13:30 djm Exp $ */
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

#ifndef _SSH_GSS_H
#define _SSH_GSS_H

#ifndef GSSAPI

struct kexgss {
};

#else

#ifdef HAVE_GSSAPI_H
#include <gssapi.h>
#elif defined(HAVE_GSSAPI_GSSAPI_H)
#include <gssapi/gssapi.h>
#endif

#ifdef KRB5
# ifndef HEIMDAL
#  ifdef HAVE_GSSAPI_GENERIC_H
#   include <gssapi_generic.h>
#  elif defined(HAVE_GSSAPI_GSSAPI_GENERIC_H)
#   include <gssapi/gssapi_generic.h>
#  endif

/* Old MIT Kerberos doesn't seem to define GSS_NT_HOSTBASED_SERVICE */

#  if !HAVE_DECL_GSS_C_NT_HOSTBASED_SERVICE
#   define GSS_C_NT_HOSTBASED_SERVICE gss_nt_service_name
#  endif /* !HAVE_DECL_GSS_C_NT_... */

# endif /* !HEIMDAL */
#endif /* KRB5 */

struct kexgss {
	gss_OID mech;	/* Saved on first use */
	gss_name_t kgname;	/* Saved on first use */
	char	*client;
	char	*host;
	char	*deleg_creds;
	time_t  tgt_expiration;
	time_t  tkt_expiration;
};

/* draft-ietf-secsh-gsskeyex-06 */
#define SSH2_MSG_USERAUTH_GSSAPI_RESPONSE		60
#define SSH2_MSG_USERAUTH_GSSAPI_TOKEN			61
#define SSH2_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE	63
#define SSH2_MSG_USERAUTH_GSSAPI_ERROR			64
#define SSH2_MSG_USERAUTH_GSSAPI_ERRTOK			65
#define SSH2_MSG_USERAUTH_GSSAPI_MIC			66

#define SSH_GSS_OIDTYPE 0x06

#define SSH2_MSG_KEXGSS_INIT                            30
#define SSH2_MSG_KEXGSS_CONTINUE                        31
#define SSH2_MSG_KEXGSS_COMPLETE                        32
#define SSH2_MSG_KEXGSS_HOSTKEY                         33
#define SSH2_MSG_KEXGSS_ERROR                           34
#define SSH2_MSG_KEXGSS_GROUPREQ			40
#define SSH2_MSG_KEXGSS_GROUP				41
#define KEXGSS						"gss-"
#define KEX_GSS_GRP1_SHA1_ID				KEXGSS "group1-sha1-"
#define KEX_GSS_GRP14_SHA1_ID				KEXGSS "group14-sha1-"
#define KEX_GSS_GEX_SHA1_ID				KEXGSS "gex-sha1-"
#define KEX_GSS_GRP14_SHA256_ID				KEXGSS "group14-sha256-"
#define KEX_GSS_GRP16_SHA512_ID				KEXGSS "group16-sha512-"
#define KEX_GSS_GRP18_SHA512_ID				KEXGSS "group18-sha512-"
#define KEX_GSS_C25519_SHA256_ID			KEXGSS "curve25519-sha256-"

typedef struct {
	struct passwd *owner;
} ssh_gssapi_ccache;

typedef struct {
	gss_buffer_desc displayname;
        char *formattedname; /* For SSH_GSSAPI_NAME env var, authorized_keys */
	gss_cred_id_t creds;
	gss_OID mechoid;
	gss_OID initial_mechoid;
	gss_name_t cgname;
	struct ssh_gssapi_mech_struct *mech;
	ssh_gssapi_ccache store;
	int used;
	int updated;
} ssh_gssapi_client;

typedef struct ssh_gssapi_mech_struct {
	char *enc_name;
	char *name;
	gss_OID_desc oid;
	int (*dochild) (ssh_gssapi_client *);
	int (*userok) (ssh_gssapi_client *, const char *);
	int (*isuser) (ssh_gssapi_client *, const char *);
	void (*storecreds) (ssh_gssapi_client *);
	int (*updatecreds) (ssh_gssapi_ccache *, ssh_gssapi_client *);
	const char *(*formatname) (ssh_gssapi_client *);
} ssh_gssapi_mech;

typedef struct {
	OM_uint32	major; /* both */
	OM_uint32	minor; /* both */
	gss_ctx_id_t	context; /* both */
	gss_name_t	gname; /* both */
	gss_OID		oid; /* client */
	gss_cred_id_t	creds; /* server */
	gss_name_t	client; /* server */
	gss_cred_id_t	client_creds; /* both */
} Gssctxt;

extern ssh_gssapi_mech *supported_mechs[];
extern Gssctxt *gss_kex_context;

int  ssh_gssapi_check_oid(Gssctxt *, void *, size_t);
void ssh_gssapi_set_oid_data(Gssctxt *, void *, size_t);
void ssh_gssapi_set_oid(Gssctxt *, gss_OID);
void ssh_gssapi_supported_oids(gss_OID_set *);
ssh_gssapi_mech *ssh_gssapi_get_ctype(Gssctxt *);
void ssh_gssapi_prepare_supported_oids(void);
OM_uint32 ssh_gssapi_test_oid_supported(OM_uint32 *, gss_OID, int *);

struct sshbuf;
int ssh_gssapi_get_buffer_desc(struct sshbuf *, gss_buffer_desc *);
int sshpkt_get_buffer_desc(struct ssh *, gss_buffer_desc *);

OM_uint32 ssh_gssapi_import_name(Gssctxt *, const char *);
OM_uint32 ssh_gssapi_init_ctx(Gssctxt *, char *,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_accept_ctx(Gssctxt *,
    gss_buffer_desc *, gss_buffer_desc *, OM_uint32 *);
OM_uint32 ssh_gssapi_getclient(Gssctxt *, ssh_gssapi_client *);
void ssh_gssapi_error(Gssctxt *);
void ssh_log_gssapi_errors(int);
char *ssh_gssapi_display_error(OM_uint32, OM_uint32, gss_OID);
char *ssh_gssapi_last_error(Gssctxt *, OM_uint32 *, OM_uint32 *);
void ssh_gssapi_build_ctx(Gssctxt **);
void ssh_gssapi_delete_ctx(Gssctxt **);
OM_uint32 ssh_gssapi_sign(Gssctxt *, gss_buffer_t, gss_buffer_t);
void ssh_gssapi_buildmic(struct sshbuf *, const char *,
    const char *, const char *);
int ssh_gssapi_check_mechanism(Gssctxt **, gss_OID, const char *, const char *,
    gss_name_t);
OM_uint32 ssh_gssapi_client_identity(Gssctxt *, const char *, gss_name_t);
int ssh_gssapi_credentials_updated(Gssctxt *, struct kexgss *);

/* In the server */
typedef int ssh_gssapi_check_fn(Gssctxt **, gss_OID, const char *, 
    const char *, gss_name_t);
char *ssh_gssapi_kex_mechs(gss_OID_set, ssh_gssapi_check_fn *, const char *,
    const char *, gss_name_t);
gss_OID ssh_gssapi_id_kex(Gssctxt *, char *, int);
int ssh_gssapi_server_check_mech(Gssctxt **,gss_OID, const char *, 
    const char *, gss_name_t);
OM_uint32 ssh_gssapi_server_ctx(Gssctxt **, gss_OID);
int ssh_gssapi_userok(char *, struct passwd *);
OM_uint32 ssh_gssapi_checkmic(Gssctxt *, gss_buffer_t, gss_buffer_t);
void ssh_gssapi_do_child(char ***, u_int *);
void ssh_gssapi_cleanup_creds(void);
void ssh_gssapi_storecreds(void);
char *ssh_gssapi_displayname(void);

char *ssh_gssapi_server_mechanisms(void);
int ssh_gssapi_oid_table_ok(void);

int ssh_gssapi_update_creds(ssh_gssapi_ccache *store);
void ssh_gssapi_rekey_creds(void);
void ssh_free_kexgss(struct kexgss *);

int ssh_gssapi_generic_userok(ssh_gssapi_client *, const char *);
int ssh_gssapi_generic_isuser(ssh_gssapi_client *, const char *);
void ssh_gssapi_generic_storecreds(ssh_gssapi_client *);
int ssh_gssapi_generic_updatecreds(ssh_gssapi_ccache *, ssh_gssapi_client *);
const char *ssh_gssapi_generic_formatname(ssh_gssapi_client *);

#endif /* GSSAPI */

#endif /* _SSH_GSS_H */
