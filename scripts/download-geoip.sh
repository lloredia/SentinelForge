#!/usr/bin/env bash
# Download MaxMind GeoLite2 City and ASN databases.
# GeoLite2 is not redistributed with this repository. A free MaxMind license
# key is required: https://www.maxmind.com/en/geolite2/signup
set -euo pipefail

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "Set MAXMIND_LICENSE_KEY to your MaxMind license key." >&2
  exit 1
fi

dest="${1:-data}"
mkdir -p "$dest"

download_edition() {
  local edition="$1"
  local tmp
  tmp="$(mktemp -d)"
  # Do not print curl's stderr: it can include the license key in the URL.
  if ! curl --silent --show-error --fail --retry 2 --retry-delay 2 \
    --output "$tmp/db.tar.gz" \
    "https://download.maxmind.com/app/geoip_download?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
    2>/dev/null; then
    rm -rf "$tmp"
    echo "MaxMind download failed for ${edition}. Check MAXMIND_LICENSE_KEY and the edition name." >&2
    exit 1
  fi
  tar -xzf "$tmp/db.tar.gz" -C "$tmp"
  find "$tmp" -type f -name '*.mmdb' -exec cp {} "$dest/" \;
  rm -rf "$tmp"
  echo "Installed ${edition} into ${dest}/"
}

download_edition "GeoLite2-City"
download_edition "GeoLite2-ASN"
