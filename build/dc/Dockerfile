# Samba, acting as an Active Directory Domain Controller, in a single Linux container.
# It provisions the realm VERTEX.LAB at first start (idempotent), plants a
# low-privilege user (d.laurent) that holds GenericAll over a higher-value user (b.whitfield),
# a bystander user (n.castellano) with no such control, and an archive share only b.whitfield
# may read. The ACL tooling (ldb-tools, ldap-utils, impacket's dacledit) ships in the image so
# the lab's check can prove the control path from inside the DC.
FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

# Preseed krb5 so its package install never prompts.
RUN set -eux; \
    echo "krb5-config krb5-config/default_realm string VERTEX.LAB" | debconf-set-selections; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        samba samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient ldb-tools \
        winbind libnss-winbind libpam-winbind \
        krb5-user krb5-config ldap-utils \
        python3 python3-venv \
        dnsutils procps iproute2 ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    # The AD DC runs as the single `samba` process, never the standalone smbd/nmbd/winbind
    # units, so make sure none of those can start on their own.
    rm -f /etc/samba/smb.conf

# impacket (pinned) in its own venv: a student enumerates the abusable ACE with its dacledit.py
# (read the DACL of b.whitfield, spot d.laurent's GenericAll) and can drive the takeover with
# owneredit.py / dacledit.py too. The lab's self-contained check uses Samba-native tooling
# (samba-tool dsacl, net rpc password), so the check never depends on impacket.
RUN set -eux; \
    python3 -m venv /opt/impacket-venv; \
    /opt/impacket-venv/bin/pip install --no-cache-dir wheel; \
    /opt/impacket-venv/bin/pip install --no-cache-dir "impacket==0.13.1"; \
    test -x /opt/impacket-venv/bin/dacledit.py

COPY archive-share.conf /opt/aclabuse/archive-share.conf
COPY check.sh           /opt/aclabuse/check.sh
COPY entrypoint.sh      /opt/aclabuse/entrypoint.sh
RUN chmod +x /opt/aclabuse/entrypoint.sh /opt/aclabuse/check.sh

ENV HOME=/root

# AD/Kerberos surface.
EXPOSE 53/tcp 53/udp 88/tcp 88/udp 389/tcp 445/tcp 464/tcp 464/udp 636/tcp 3268/tcp

CMD ["/opt/aclabuse/entrypoint.sh"]
