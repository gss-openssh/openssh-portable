#	$OpenBSD: kextype.sh,v 1.6 2015/03/24 20:19:15 markus Exp $
#	Placed in the Public Domain.

tid="login with different key exchange algorithms"

TIME=/usr/bin/time
cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak
cp $OBJ/ssh_proxy $OBJ/ssh_proxy_bak

# Make server accept all key exchanges.
#
# The gss kexes require GSS creds, and their names include suffixes based on the
# mechanism oids from the GSS library.  We could fix the -Q flag to return only
# the full names when the client has gss credentials, but then we'd also need
# a server keytab file, which absent a convenient KDC, requires "kimpersonate"
# or similar, which is not widely installed.  So just skip the GSS KEX tests.
#
ALLKEX=`${SSH} -Q kex | egrep -v '^gss'`
KEXOPT=`echo $ALLKEX | tr ' ' ,`
echo "KexAlgorithms=$KEXOPT" >> $OBJ/sshd_proxy

tries="1 2 3 4"
for k in $ALLKEX; do
	verbose "kex $k"
	for i in $tries; do
		${SSH} -F $OBJ/ssh_proxy -o KexAlgorithms=$k x true
		if [ $? -ne 0 ]; then
			fail "ssh kex $k"
		fi
	done
done

