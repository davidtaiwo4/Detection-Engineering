#!/usr/bin/env bash
set -euo pipefail

tag="${WAZUH_TAG:-v4.14.6}"
destination="${1:-wazuh-docker}"
if [ -e "$destination" ]; then
  echo "refusing to overwrite $destination" >&2
  exit 1
fi
git clone --branch "$tag" --depth 1 https://github.com/wazuh/wazuh-docker.git "$destination"
install -d "$destination/single-node/config/wazuh_cluster"
install -m 0644 overlays/local_rules.xml "$destination/single-node/config/wazuh_cluster/local_rules.xml"
install -m 0644 overlays/local_decoder.xml "$destination/single-node/config/wazuh_cluster/local_decoder.xml"
printf '%s\n' "$tag" > "$destination/NETFORGE-PINNED-REF"
printf '%s\n' 'Generate certificates with the pinned repository instructions before docker compose up.'
