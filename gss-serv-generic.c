/*
 * Copyright (c) 2019 Two Sigma Open Source, LLC. All rights reserved.
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

/*
 * This file provides default implementations of methods for struct
 * ssh_gssapi_mech_struct.
 *
 * Some mechanisms might need to provide mechanism-specific implementations of
 * those methods, but for Kerberos we can rely entirely on standard, generic
 * GSS-API functions (including standardized GSS-API v2 update 1 extensions).
 *
 * The most likely method to require mechanism-specific implementations is the
 * name formatting method.
 */

#include <sys/types.h>

#include <string.h>

#include "hostfile.h"
#include "auth.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"

#include "ssh-gss.h"

extern ServerOptions options;

#ifdef HAVE_GSSAPI_EXT
# include <gssapi_ext.h>
#endif

/*
 * Returns true if the client principal is allowed to login to the requested
 * user account, otherwise returns 0
 */
int
ssh_gssapi_generic_userok(ssh_gssapi_client *client, const char *username)
{
	int ret;

	ret = gss_userok(client->cgname, username);
	do_log2(SYSLOG_LEVEL_INFO, "Login to user %s %s by gss_userok()",
		username, ret ? "granted" : "rejected");
	return ret;
}

/*
 * Returns true if the client principal has a singular user account name that
 * happens to be the same as the one they are trying to login to, otherwise
 * returns 0.
 */
int
ssh_gssapi_generic_isuser(ssh_gssapi_client *client, const char *username)
{
	gss_buffer_desc localname;
	OM_uint32 minor;
	int ret;

	if (gss_localname(&minor, client->cgname, client->initial_mechoid,
			  &localname) != GSS_S_COMPLETE)
	    return 0;

	ret = strlen(username) == localname.length &&
	    strncmp(username, localname.value, localname.length) == 0;
	gss_release_buffer(&minor, &localname);
	return ret;
}


/* This writes out any forwarded credentials from the structure populated
 * during userauth. Called after we have setuid to the user */

void
ssh_gssapi_generic_storecreds(ssh_gssapi_client *client)
{
	OM_uint32 major, minor;

	if (client->creds == GSS_C_NO_CREDENTIAL) {
		debug("No delegated credentials to store");
		return;
	}

	/*
	 * XXX Add support for configuration of GSS cred store in sshd_config,
	 * then use gss_store_cred_into(), then record the store info in
	 * client->store.
	 */
	major = gss_store_cred(&minor, client->creds, GSS_C_INITIATE,
			       client->mechoid, 1, 1, NULL, NULL);
	if (major == GSS_S_COMPLETE) {
		debug("Stored delegated credentials into default store");
		debug2("%s: gss_store_cred(%.*s) = (%lx, %lx)", __func__,
		    (int)client->displayname.length, (char *)client->displayname.value,
		    (u_long)major, (u_long)minor);
	} else {
		char *s;

		s = ssh_gssapi_display_error(major, minor, client->mechoid);
		do_log2(SYSLOG_LEVEL_INFO, "Failed to store delegated "
			"credentials: %s", s);
		free(s);
	}
}

int
ssh_gssapi_generic_updatecreds(ssh_gssapi_ccache *store,
    ssh_gssapi_client *client)
{
	OM_uint32 major, minor;
	gss_name_t def_cred_name = GSS_C_NO_NAME;

	major = gss_inquire_cred_by_mech(&minor, GSS_C_NO_CREDENTIAL,
					 &client->mech->oid, &def_cred_name,
					 NULL, NULL, NULL);
	if (major == GSS_S_COMPLETE) {
		int eq = 0;

		(void) gss_compare_name(&minor, def_cred_name, client->cgname,
					&eq);
		gss_release_name(&minor, &def_cred_name);
		if (!eq) {
			debug("Not storing delegated credentials in rekey "
			      "because they are for a different name than in "
			      "the initial delegation");
			return 0;
		}
	}

	ssh_gssapi_generic_storecreds(client);
	return 1;
}

const char *
ssh_gssapi_generic_formatname(ssh_gssapi_client *client)
{
	char *s = NULL;

	if (client->formattedname)
		return client->formattedname;
	if (client->displayname.value == NULL)
		return NULL;
	if (asprintf(&s, "%s:%.*s", client->mech->name,
		     (int)client->displayname.length,
                     (char *)client->displayname.value) == -1)
		s = NULL;
	client->formattedname = s;
	return s;
}

#endif /* GSSAPI */
