#!/bin/sh
# Bring up a throwaway Kerberos realm and a slapd accepting SASL/GSSAPI binds,
# for t/gssapi.t. Everything runs unprivileged out of one directory.
#
#   t/gssapi/env.sh start [dir]   # prints the variables to export
#   t/gssapi/env.sh stop  [dir]
#
# Needs MIT krb5 (krb5-kdc, krb5-admin-server, krb5-user), slapd, ldap-utils
# and the Cyrus SASL GSSAPI plugin (libsasl2-modules-gssapi-mit on
# Debian/Ubuntu).

set -eu

cmd=${1:-start}
dir=${2:-${TMPDIR:-/tmp}/lua-resty-ldap-gssapi}
# The daemons change to / and the printed paths are used from elsewhere, so
# every path must be absolute; it is also canonical (no ./, .. or symlinks
# in the parent), as stop matches it against the daemons' command lines.
canonical_dir() {
    case $dir in
    /*) ;;
    *) dir=$PWD/$dir ;;
    esac
    if [ -d "$(dirname "$dir")" ]; then
        dir=$(cd "$(dirname "$dir")" && pwd -P)/$(basename "$dir")
    fi
    # The path goes unquoted into slapd.conf, kdc.conf, kadmin queries and
    # the exports below, none of which take shell-style quoting.
    case $dir in
    *[!A-Za-z0-9/._-]*)
        echo "$0: unsupported characters in directory '$dir' (use A-Za-z0-9/._-)" >&2
        exit 2
        ;;
    esac
}
canonical_dir

REALM=EXAMPLE.ORG
KDC_PORT=${KDC_PORT:-8888}
LDAP_PORT=${LDAP_PORT:-3890}
HOST=localhost
PATH=$PATH:/usr/sbin:/sbin

# start wipes the directory, and the default one lives in a shared /tmp: only
# ever touch a directory this script created, owned by the invoking user
MARKER=.lua-resty-ldap-gssapi
managed_dir() {
    [ -d "$dir" ] && [ -O "$dir" ] && [ -f "$dir/$MARKER" ]
}

stop() {
    managed_dir || return 0
    for p in "$dir/slapd.pid" "$dir/krb5kdc.pid"; do
        if [ -f "$p" ]; then
            pid=$(cat "$p")
            # signal only our daemon, not whatever process has the PID now
            case $pid in
            ''|*[!0-9]*) ;;
            *)
                if ps -o args= -p "$pid" 2>/dev/null | grep -qF "$dir/"; then
                    kill "$pid" 2>/dev/null || true
                    # wait for it to exit, so a restart finds its port free
                    for _ in $(seq 1 25); do
                        kill -0 "$pid" 2>/dev/null || break
                        sleep 0.2
                    done
                fi
                ;;
            esac
        fi
        rm -f "$p"
    done
}

if [ "$cmd" = stop ]; then
    stop
    exit 0
fi
if [ "$cmd" != start ]; then
    echo "usage: $0 start|stop [dir]" >&2
    exit 2
fi

if [ -e "$dir" ] && ! managed_dir; then
    if ! { [ -d "$dir" ] && [ -O "$dir" ] && [ -z "$(ls -A "$dir")" ]; }; then
        echo "$dir exists and is not an environment created by $0; not replacing it" >&2
        exit 1
    fi
fi
stop
rm -rf "$dir"
# no -p for the directory itself: fail if someone else creates it meanwhile
mkdir -p "$(dirname "$dir")"
canonical_dir
(umask 077 && mkdir "$dir")
mkdir "$dir/kdc" "$dir/ldap"
: > "$dir/$MARKER"

cat > "$dir/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    dns_canonicalize_hostname = false
    rdns = false
    qualify_shortname = ""
    udp_preference_limit = 1

[realms]
    $REALM = {
        kdc = 127.0.0.1:$KDC_PORT
    }

[domain_realm]
    $HOST = $REALM
    otherhost = $REALM
EOF

cat > "$dir/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT

[realms]
    $REALM = {
        database_name = $dir/kdc/principal
        key_stash_file = $dir/kdc/stash
        acl_file = $dir/kdc/kadm5.acl
        supported_enctypes = aes256-cts-hmac-sha1-96:normal
    }

[logging]
    kdc = FILE:$dir/krb5kdc.log
EOF

export KRB5_CONFIG="$dir/krb5.conf"
export KRB5_KDC_PROFILE="$dir/kdc.conf"

kdb5_util create -s -r "$REALM" -P masterpassword >/dev/null
kadmin.local -q "addprinc -randkey ldap/$HOST" >/dev/null
kadmin.local -q "ktadd -k $dir/ldap.keytab ldap/$HOST" >/dev/null
# a service the KDC issues tickets for, but slapd has no key for
kadmin.local -q "addprinc -randkey ldap/otherhost" >/dev/null
kadmin.local -q "addprinc -randkey user01" >/dev/null
kadmin.local -q "ktadd -k $dir/client.keytab user01" >/dev/null

# from here on a failed startup must not leave the daemons running
trap stop EXIT
krb5kdc -P "$dir/krb5kdc.pid"

cat > "$dir/slapd.conf" <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema

modulepath /usr/lib/ldap
moduleload back_mdb

pidfile $dir/slapd.pid
sasl-host $HOST
sasl-realm $REALM
authz-regexp "^uid=([^,]+),cn=$REALM,cn=gssapi,cn=auth\$" "uid=\$1,ou=users,dc=example,dc=org"

database mdb
suffix "dc=example,dc=org"
rootdn "cn=admin,dc=example,dc=org"
rootpw adminpassword
directory $dir/ldap
# user01's entry is readable only by user01 itself, so a search proves which
# identity a bind established
access to dn.exact="uid=user01,ou=users,dc=example,dc=org"
    by dn.exact="uid=user01,ou=users,dc=example,dc=org" read
    by * none
access to * by * read
EOF

cat > "$dir/base.ldif" <<EOF
dn: dc=example,dc=org
objectClass: dcObject
objectClass: organization
o: example
dc: example

dn: ou=users,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: uid=user01,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
uid: user01
cn: user01
sn: user01
EOF

slapadd -f "$dir/slapd.conf" -l "$dir/base.ldif" >/dev/null 2>&1

# slapd reads the service keytab through the krb5 library
KRB5_KTNAME="$dir/ldap.keytab" slapd -f "$dir/slapd.conf" -h "ldap://127.0.0.1:$LDAP_PORT/"

# a client credential cache for the test worker processes
kinit -k -t "$dir/client.keytab" -c "$dir/ccache" user01

ready=
for _ in $(seq 1 50); do
    if KRB5CCNAME="$dir/ccache" ldapwhoami -N -Q -Y GSSAPI -H "ldap://$HOST:$LDAP_PORT" >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.2
done
if [ -z "$ready" ]; then
    echo "slapd does not accept GSSAPI binds; see $dir/krb5kdc.log" >&2
    KRB5CCNAME="$dir/ccache" ldapwhoami -N -Y GSSAPI -H "ldap://$HOST:$LDAP_PORT" >&2 || true
    exit 1
fi

trap - EXIT

cat <<EOF
export KRB5_CONFIG=$dir/krb5.conf
export KRB5CCNAME=$dir/ccache
export TEST_LDAP_GSSAPI_HOST=$HOST
export TEST_LDAP_GSSAPI_PORT=$LDAP_PORT
EOF
