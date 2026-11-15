# Signing OxPanel packages

This is the procedure for signing the RPM packages of a release. It is done by
the person who holds the release key, on their own machine. Nothing in the build
signs packages automatically, and the private key never goes into a repository,
a container image or a build volume.

Signing proves who built a package. The `SHA256SUMS` file in the release bundle
only detects a damaged download; anyone who can replace a package can replace
that file too.

## What you need

- `gnupg2` and `rpm-sign` on the machine that signs:

  ```bash
  sudo dnf install gnupg2 rpm-sign
  ```

- The release bundle produced by `make dist` (`dist/release/`), containing the
  packages to sign.

## One-time setup

### 1. Create the release key

```bash
gpg --full-generate-key
```

Answer the questions as follows:

| Question | Answer |
|---|---|
| Kind of key | `RSA (sign only)` |
| Key size | `4096` |
| Expiry | `3y` (renew before it expires; see "Renewing the key") |
| Real name | `OxServers Packages` |
| Email | the address you publish for package questions |
| Passphrase | a long one, stored in a password manager |

RSA 4096 is used because every RPM version on AlmaLinux 9 verifies it.

Note the key's fingerprint; you will publish it:

```bash
gpg --fingerprint "OxServers Packages"
```

### 2. Tell rpm which key to use

Put this line in `~/.rpmmacros` (the name must match the key exactly):

```
%_gpg_name OxServers Packages
```

### 3. Export the public key

```bash
gpg --export --armor "OxServers Packages" > RPM-GPG-KEY-oxpanel
```

This file is public. It ships in the release bundle and is published wherever
the release is downloaded from.

### 4. Back up the private key

```bash
gpg --export-secret-keys --armor "OxServers Packages" > oxpanel-release-key.private.asc
gpg --gen-revoke "OxServers Packages" > oxpanel-release-key.revoke.asc
```

Store both files offline (for example on an encrypted USB drive kept away from
the signing machine), then delete them from the disk. Without the private key
you cannot sign an update that existing servers will accept. The revocation
certificate is what you publish if the key is ever stolen.

## Every release

Run these in the release bundle directory (`dist/release/`).

### 1. Sign the packages

```bash
rpmsign --addsign oxpanel-daemon-*.rpm oxpanel-panel-*.rpm
```

`rpmsign` asks for the key's passphrase. If the bundle has no panel package,
sign the engine package alone.

### 2. Check the signatures

Check against a clean rpm database, so the result does not depend on keys that
happen to be installed on your machine:

```bash
tmp=$(mktemp -d)
rpm --dbpath "$tmp" --import RPM-GPG-KEY-oxpanel
rpm --dbpath "$tmp" -K oxpanel-*.rpm
rm -rf "$tmp"
```

Each line must end with `digests signatures OK`. If it says `SIGNATURES NOT OK`
or mentions `NOKEY`, stop: the package is unsigned or was signed with another
key.

### 3. Add the public key and refresh the checksums

Signing changes the package files, so the old checksums no longer match.

```bash
cp /path/to/RPM-GPG-KEY-oxpanel .
sha256sum -- * | grep -v ' SHA256SUMS$' | sort -k2 > SHA256SUMS
sha256sum -c --quiet SHA256SUMS
```

### 4. Sign the checksum file

```bash
gpg --local-user "OxServers Packages" --armor --detach-sign SHA256SUMS
```

This creates `SHA256SUMS.asc`, which covers `install.sh` and the handbook as
well as the packages.

### 5. Publish

Upload the whole directory. The panel package is proprietary: it must not be
uploaded to the public engine repository or to any public release page.

## What the person installing does

Until the installer checks signatures itself (see "Not automated yet"), the
check is manual:

```bash
sudo rpm --import RPM-GPG-KEY-oxpanel
rpm -K oxpanel-*.rpm                       # must say: digests signatures OK
gpg --import RPM-GPG-KEY-oxpanel
gpg --verify SHA256SUMS.asc SHA256SUMS     # must say: Good signature
sha256sum -c SHA256SUMS
sudo ./install.sh
```

The fingerprint printed by `gpg --verify` must match the one published on the
project's site. A key that arrives in the same download as the packages proves
nothing on its own; the fingerprint has to come from a second place.

## Renewing the key

Before the key expires, extend it and publish the public key again:

```bash
gpg --edit-key "OxServers Packages"    # then: expire, <new period>, save
gpg --export --armor "OxServers Packages" > RPM-GPG-KEY-oxpanel
```

The key keeps its fingerprint. Servers that imported the old public key need
the refreshed file to accept packages signed after the old expiry date.

## If the key is lost or stolen

- Lost: create a new key, publish its public key and fingerprint, and tell
  administrators to import it. Updates signed with the new key are refused
  until they do.
- Stolen: publish the revocation certificate, then do the same as for a lost
  key. Treat every package signed after the theft as untrusted.

## Not automated yet

- `install.sh` verifies `SHA256SUMS` but not the package signature.
- There is no `make sign` target; the steps above are run by hand.
- The dnf repository settings in `install.sh` (`OXPANEL_REPO_GPGKEY`,
  `gpgcheck=1`) are placeholders until a package repository is hosted. When it
  is, the repository metadata is signed with the same key
  (`gpg --detach-sign --armor repodata/repomd.xml`).
