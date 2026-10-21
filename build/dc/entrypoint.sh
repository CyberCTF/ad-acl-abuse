#!/bin/bash
# Brings the Samba AD DC up deterministically and idempotently:
#   1. provisions realm NORTH.SEVENKINGDOMS.LOCAL once (skipped on restart),
#   2. creates the low-privilege foothold user `hodor`, the higher-value target
#      `maester.luwin`, and a bystander `jon.snow` with no special control,
#   3. grants hodor GenericAll over maester.luwin (the abusable ACE this lab is about),
#   4. plants the flag in an archive share only maester.luwin may read,
#   5. runs the single `samba` AD DC process in the foreground.
# Re-running it against an already-provisioned DC changes nothing (safe restart).
set -euo pipefail

REALM="NORTH.SEVENKINGDOMS.LOCAL"
DOMAIN="NORTH"
# DC administrator password: infrastructure only, never shown to the student.
ADMIN_PASS="DCAdm1n#Winterfell2024"
# Student's low-privilege foothold account (handed out in the lab message).
HODOR_USER="hodor"
HODOR_PASS="Hodor123!"
# Higher-value target: holds the archive share; hodor controls it via GenericAll.
TARGET_USER="maester.luwin"
TARGET_PASS="Lu0win#Citadel2024"
# A bystander domain user with no control edge, used to prove the ACE is what matters.
BYSTANDER_USER="jon.snow"
BYSTANDER_PASS="Ygritte#Wall2024"

PRIVATE_DIR="/var/lib/samba/private"
STAMP="${PRIVATE_DIR}/.isoloom-provisioned"

log() { echo "[dc] $*" >&2; }

if [ ! -f "${STAMP}" ]; then
  log "provisioning ${REALM} ..."
  rm -f /etc/samba/smb.conf
  # posix:eadb keeps NT ACLs in a tdb instead of security.* xattrs, so provisioning and the
  # file server work in an unprivileged container (no CAP_SYS_ADMIN). "ldap server require
  # strong auth = no" lets the student enumerate the object's DACL over plain LDAP from the
  # attack box. Both --options persist into the generated smb.conf, so the daemon uses them too.
  samba-tool domain provision \
    --use-rfc2307 \
    --realm="${REALM}" \
    --domain="${DOMAIN}" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --host-name=dc \
    --adminpass="${ADMIN_PASS}" \
    --option="posix:eadb=/var/lib/samba/eadb.tdb" \
    --option="ldap server require strong auth = no" >/dev/null

  # Kerberos client config and resolver point the DC at its own internal DNS.
  cp -f "${PRIVATE_DIR}/krb5.conf" /etc/krb5.conf

  # Publish the archive share that guards the flag.
  cat /opt/aclabuse/archive-share.conf >> /etc/samba/smb.conf

  touch "${STAMP}"
  log "provisioning done."
else
  log "already provisioned; reusing ${PRIVATE_DIR}."
fi

# Resolver: the DC resolves its own realm through Samba's internal DNS.
printf 'nameserver 127.0.0.1\nsearch north.sevenkingdoms.local\n' > /etc/resolv.conf 2>/dev/null || true
grep -q 'dc.north.sevenkingdoms.local' /etc/hosts 2>/dev/null || \
  printf '127.0.0.1 dc.north.sevenkingdoms.local dc\n' >> /etc/hosts 2>/dev/null || true

# Users are created offline against the local sam.ldb, so this works whether or not the samba
# process is already running.
if ! samba-tool user list 2>/dev/null | grep -qx "${HODOR_USER}"; then
  log "creating foothold user ${HODOR_USER}"
  samba-tool user create "${HODOR_USER}" "${HODOR_PASS}" >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${TARGET_USER}"; then
  log "creating target user ${TARGET_USER}"
  samba-tool user create "${TARGET_USER}" "${TARGET_PASS}" \
    --description="Maester of Winterfell; keeper of the archive" >/dev/null
fi

if ! samba-tool user list 2>/dev/null | grep -qx "${BYSTANDER_USER}"; then
  log "creating bystander user ${BYSTANDER_USER}"
  samba-tool user create "${BYSTANDER_USER}" "${BYSTANDER_PASS}" >/dev/null
fi

# The abusable ACE: grant hodor GenericAll over maester.luwin. samba-tool dsacl set merges the
# SDDL ACE into the target's nTSecurityDescriptor, so hodor gains full control (which includes
# the reset-password right) over the higher-value account. Idempotent: only added if absent.
TARGET_DN="$(samba-tool user show "${TARGET_USER}" --attributes=distinguishedName 2>/dev/null \
  | awk -F': ' '/^dn:/{print $2; exit}')"
HODOR_SID="$(samba-tool user show "${HODOR_USER}" --attributes=objectSid 2>/dev/null \
  | awk -F': ' '/^objectSid:/{print $2; exit}')"
if [ -z "${TARGET_DN}" ] || [ -z "${HODOR_SID}" ]; then
  log "FATAL: could not resolve target DN or hodor SID (DN='${TARGET_DN}' SID='${HODOR_SID}')"
  exit 1
fi
if ! samba-tool dsacl get --objectdn="${TARGET_DN}" 2>/dev/null | grep -qi "${HODOR_SID}"; then
  log "granting ${HODOR_USER} (${HODOR_SID}) GenericAll over ${TARGET_USER}"
  samba-tool dsacl set --objectdn="${TARGET_DN}" \
    --sddl="(A;;GA;;;${HODOR_SID})" >/dev/null
fi

# Passwords never expire, so the lab behaves the same on day 1 and day 60.
samba-tool user setexpiry "${HODOR_USER}" --noexpiry >/dev/null 2>&1 || true
samba-tool user setexpiry "${TARGET_USER}" --noexpiry >/dev/null 2>&1 || true
samba-tool user setexpiry "${BYSTANDER_USER}" --noexpiry >/dev/null 2>&1 || true

# Plant the flag inside the archive. CTF_FLAG_MAIN is delivered by the launcher at /ctf/flag
# (Isoloom's sensitive-input-as-file mechanism); fall back to a dev flag for a bare run.
mkdir -p /srv/archive
if [ -s /ctf/flag ]; then
  cp -f /ctf/flag /srv/archive/flag.txt
else
  printf 'FLAG{dev-ad-acl-genericall-maester-luwin}\n' > /srv/archive/flag.txt
fi
chmod 0444 /srv/archive/flag.txt

log "starting samba (AD DC) ..."
exec samba --interactive --no-process-group
