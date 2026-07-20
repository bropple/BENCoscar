# Encrypting the database at rest

**Status: researched, not built. Optional by design.**

This documents what at-rest encryption would and would not buy a BENCoscar
deployment, the three approaches investigated, and why one of them is dead. It
is deliberately honest about the narrowness of the prize, because "encrypt the
database" sounds like it protects message content and here it does not.

Nothing in BENCoscar needs to change to support this. The database sits on an
encrypted volume and the application never knows — which is what makes it
optional. See §6 for the one small guard worth adding anyway.

## 1. What is actually at risk

| Content | State today |
|---|---|
| Message bodies (`offlineMessage.message`) | **already ciphertext** — BENCchat seals before sending; the server stores the marshalled SNAC |
| Identity backups (`keyDirIdentityBackups`) | **already encrypted** under the user's recovery key |
| Key directory manifests | public keys, deliberately public |
| Passwords (`user.passHash`) | argon2id |
| **Buddy lists, profiles, screen names, message metadata** | **plaintext** |

So at-rest encryption here protects **metadata, not content**: who talks to
whom, who is on whose list, and when. That is worth something. It is not what
most people picture.

Backups are already handled separately and better — `scripts/backup-db.sh` is
asymmetric, so the server can create backups it cannot read. That was the
leakiest path and it is closed.

## 2. What the threat actually is

**A leaked or copied block-storage snapshot.** Someone obtains the disk image
without the running machine.

Explicitly NOT in scope: shell access to the running VM. Any design that
unlocks automatically must let the machine reach its own key, so a machine that
can boot unattended can always be made to hand over what it unlocked. That is
not a flaw in a particular scheme, it is what unattended unlock means.

**The whole question is therefore key custody**, not cipher choice. A key stored
on the same volume protects nothing: the snapshot contains both halves.

## 3. Ruled out: TPM / systemd-cryptenroll

On OCI, a vTPM ships with **Shielded Instances**, and Oracle's shape support
list contains only Intel and AMD x86 shapes — `VM.Standard3.Flex`,
`VM.Standard.E3`–`E6.Flex`, `VM.Optimized3.Flex` and bare-metal equivalents.
**Ampere A1 is absent.**

Independently, Shielded Instances accept only Oracle platform images and not
custom ones, which would block the modified initramfs a TPM unlock needs.

Two separate reasons, so this is not worth revisiting unless Oracle changes the
shape list.

## 4. Option A — OCI Vault + instance principals

**Confirmed:** instance principals store no credential on disk. The leaf
certificate, its private key and the intermediate are fetched at runtime from
the link-local metadata service at `169.254.169.254/opc/v2/identity/`
(`cert.pem`, `key.pem`, `intermediate.pem`).

**Confirmed and load-bearing:** OCI Vault master keys come in two protection
modes and they are **not** equivalent.

| Mode | Where the key lives | Exportable | FIPS |
|---|---|---|---|
| Software-protected | on an Oracle server | **yes** | 140-2 Level 1 |
| HSM-protected | in the HSM | no | 140-2 Level 3 |

A software-protected key gives away most of the property being bought. If this
route is taken it must be HSM-protected. Note that Oracle's documentation does
not state whether Oracle personnel can access key material in either mode.

**Unverified:** whether the metadata service is reachable from initramfs, before
the root volume mounts. Oracle documents IMDS as feeding cloud-init, which runs
after the OS is already up. No source found either way.

**Unverified:** whether a snapshot restored as a *different* instance inherits
the original's principal identity.

**What it does not protect against:** Oracle. They operate the HSM.

## 5. Option B — Clevis + Tang (preferred)

**Confirmed:** Oracle documents `clevis luks bind` on Oracle Linux, so this is a
vendor-supported path rather than community-only.

**Confirmed:** Tang never learns the key. In the McCallum-Relyea exchange the
client-side keys are never shared with the server and never traverse the
network — which is also why the connection needs no TLS. A Tang server is not a
key escrow; it holds material that is useless without the client's token, and
the client holds a token that is useless without Tang.

**Confirmed, and it corrects a common assumption:** the `sss` (Shamir) pin's
documented canonical use is **high-availability Tang** — threshold `t=1` across
two Tang URLs, so unlock succeeds if *either* is reachable. A passphrase
fallback does exist, but it is **interactive**: a human at the boot prompt,
which is useless on a headless VM at 3am.

So Tang's availability story is *redundancy*, not fallback. Doing it properly
means **two** Tang hosts.

**Unverified:** Ubuntu / `initramfs-tools` on arm64. Upstream documents dracut
only; Oracle's procedure covers only the bare `tang` pin against a root LVM
device and does not address `sss`, network-online ordering, or aarch64.

**What it protects against that Option A does not:** Oracle, if Tang runs
somewhere Oracle does not — a machine at home, another provider.

## 6. The design that avoids the hard part

Both options run into "can this work in initramfs, before root mounts?" — which
is unverified for A and undocumented-on-Ubuntu for B.

**Put the database on a separate volume and the question disappears.**

Root stays unencrypted; it holds nothing that matters. The machine boots
normally, brings up networking, unlocks the *data* volume, and only then starts
BENCoscar. No initramfs work, no interactive step, fully automatic reboots.

This works precisely because everything sensitive is one SQLite file.

### The one guard worth adding to BENCoscar

If the encrypted volume fails to mount, the directory is still there — empty —
and **SQLite will cheerfully create a fresh database on the mountpoint.** The
server then starts, healthy, with no accounts. First sign-on says the password
is wrong. Nothing errors, nothing logs anything alarming, and a subsequent
backup happily overwrites a good one with the empty database.

That is the same silent-degradation shape this project has already been bitten
by more than once, and it is worth one flag:

> refuse to CREATE a database when one was expected to exist

Optional, off by default, and independent of whether encryption is used at all —
a failed mount is a failed mount. This is the only application-level change any
of this justifies.

## 7. Recommendation

**Option B, on a separate data volume, as an optional deployment bundle** —
`scripts/benchat-luks/`, mirroring what `scripts/benchat-tls/` already is for
stunnel: documented, scripted, and not required to run a server.

Deployments that want it get key custody that Oracle is not part of. Deployments
that do not are unaffected, which matters because the honest assessment is that
this is the **lowest-value security item** on the list — bodies are already
end-to-end encrypted, backups are already asymmetric, and what remains exposed
is metadata.

One Tang host is enough to start. The second is what turns "automatic unless
Tang is down" into "automatic", and can be added later without re-encrypting
anything — `clevis luks bind` again with an `sss` policy.

## 8. Verify before building

Research was cut short during its verification pass, so these are open:

- Ubuntu `initramfs-tools` support on arm64 — likely irrelevant under §6's
  design, since a data volume unlocks after the OS is up, but confirm before
  relying on it.
- Whether `clevis-luks-askpass` and `_netdev` ordering behave on a data volume
  as expected on the distro actually deployed.
- Tang's behaviour when reachable but returning an error, as distinct from
  unreachable.
- If Option A is ever reconsidered: whether a restored snapshot inherits the
  instance principal identity. That one is load-bearing and nobody answered it.
