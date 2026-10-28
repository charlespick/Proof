#!/usr/bin/env bash
# Packages a published Linux client as proof_<version>_<arch>.deb.
#
#   packaging/debian/build-deb.sh <publish dir> <deb version> <deb arch> <output dir>
#
# The publish dir holds the self-contained single-file proof (see README.md). The deb version is ProofDebVersion
# from build/Version.proj, where a prerelease's - is already ~ so it sorts below its release.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  sed -n '2,7p' "$0" >&2
  exit 2
fi

publish=$1
version=$2
arch=$3
out=$4
here=$(cd "$(dirname "$0")" && pwd)

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT

# Debian packages install to /usr/bin, never /usr/local.
install -Dm0755 "$publish/proof" "$root/usr/bin/proof"
install -Dm0644 "$here/copyright" "$root/usr/share/doc/proof/copyright"
# The image supplies config.json, so the package owns only the directory.
install -d -m0755 "$root/etc/proof"

install -d -m0755 "$root/DEBIAN"
installed_size=$(du -sk --exclude=DEBIAN "$root" | cut -f1)
sed -e "s/@VERSION@/$version/" -e "s/@ARCH@/$arch/" -e "s/@INSTALLED_SIZE@/$installed_size/" \
  "$here/control.in" > "$root/DEBIAN/control"

mkdir -p "$out"
dpkg-deb --root-owner-group --build "$root" "$out/proof_${version}_${arch}.deb"
