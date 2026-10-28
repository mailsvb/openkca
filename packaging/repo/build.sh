#!/usr/bin/env bash
# build.sh builds the package repository served on GitHub Pages into OUT:
#
#   rpm/                an rpm-md repository for zypper and dnf, repomd.xml signed,
#                       with the openkca packages
#   rpm/openkca.repo    the repository definition zypper and dnf add
#   openkca.asc         the public key, armored
#
# It is rebuilt whole from the rpm assets of the KEEP newest GitHub releases,
# so older versions drop out as new ones are released. An rpm that is not
# signed with the key is left out: zypper and dnf would refuse it.
#
# Needs gh (GH_TOKEN), createrepo_c, rpmkeys and gpg with the signing key
# imported: GPG_KEY_ID names it, GPG_PASSPHRASE unlocks it if it has one.
# REPO_URL is where the site is served, by default the repository's Pages URL.
set -euo pipefail

out=${1:?usage: build.sh OUT}
keep=${KEEP:-5}
key=${GPG_KEY_ID:?GPG_KEY_ID names the signing key}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is owner/name}
owner=${repo%%/*}
url=${REPO_URL:-https://${owner,,}.github.io/${repo#*/}}

sign() {
    gpg --batch --yes --local-user "$key" --pinentry-mode loopback \
        --passphrase-fd 0 "$@" <<<"${GPG_PASSPHRASE:-}"
}

rm -rf "$out"
mkdir -p "$out/rpm" "$out/download"

gpg --armor --export "$key" > "$out/openkca.asc"

tags=$(gh release list --repo "$repo" --exclude-drafts --exclude-pre-releases \
    --limit "$keep" --json tagName --jq '.[].tagName')
[ -n "$tags" ] || { echo "no releases to publish" >&2; exit 1; }
for tag in $tags; do
    echo "adding $tag"
    gh release download "$tag" --repo "$repo" --dir "$out/download" \
        --pattern '*.rpm' || echo "$tag has no packages"
done

# the signatures are checked against the key alone, in a keyring of its own
rpmdb=$(mktemp -d)
trap 'rm -rf "$rpmdb"' EXIT
rpmkeys --dbpath "$rpmdb" --import "$out/openkca.asc"
shopt -s nullglob
count=0
for rpm in "$out"/download/*.rpm; do
    # an unsigned rpm passes too, on its digests alone; a signed one says so
    if result=$(rpmkeys --dbpath "$rpmdb" --checksig "$rpm" 2>&1) &&
        grep -qE 'signatures OK|pgp' <<<"$result"; then
        mv "$rpm" "$out/rpm/"
        count=$((count + 1))
    else
        echo "leaving out $(basename "$rpm"), it is not signed with the key"
    fi
done
rm -rf "$out/download"
[ "$count" -gt 0 ] || { echo "no signed packages to publish" >&2; exit 1; }

# rpm-md, for zypper and dnf
createrepo_c "$out/rpm"
sign --armor --detach-sign --output "$out/rpm/repodata/repomd.xml.asc" "$out/rpm/repodata/repomd.xml"
# zypper also looks for the key beside repomd.xml
cp "$out/openkca.asc" "$out/rpm/repodata/repomd.xml.key"
cat > "$out/rpm/openkca.repo" <<EOF
[openkca]
name=OpenKCA
baseurl=$url/rpm
type=rpm-md
enabled=1
autorefresh=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/openkca.asc
EOF

cat > "$out/index.html" <<EOF
<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenKCA packages</title>
<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}pre{background:#f4f4f4;padding:.75rem;overflow-x:auto}</style>
<h1>OpenKCA packages</h1>
<p>Signed with <a href="openkca.asc">this key</a>. The $keep newest releases are kept.</p>
<h2>openSUSE and SLES</h2>
<pre>sudo zypper addrepo $url/rpm/openkca.repo
sudo zypper refresh &amp;&amp; sudo zypper install openkca
sudo zypper update openkca</pre>
<h2>Fedora, RHEL and Rocky Linux</h2>
<pre>sudo dnf config-manager addrepo --from-repofile=$url/rpm/openkca.repo
sudo dnf install openkca</pre>
<h2>After the install</h2>
<p>The openkca service runs on <code>https://&lt;host&gt;:9443/</code>. The
initial server password is in <code>/etc/openkca/initial-password</code>, the
configuration in <code>/etc/openkca/config.yaml</code> and the databases in
<code>/var/lib/openkca</code>. Restart the service after changing the
configuration: <code>sudo systemctl restart openkca</code>.</p>
<h2>Other systems</h2>
<p>Archives for Linux, Windows and macOS are on the
<a href="https://github.com/$repo/releases/latest">releases page</a>.</p>
<p>Source: <a href="https://github.com/$repo">github.com/$repo</a></p>
</html>
EOF

echo "built $out: $count rpm packages from $(echo $tags | wc -w) releases"
