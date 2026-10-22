#!/usr/bin/env bash
# Set the passwords in cluster/.gitea.env on the running Gitea (plan task A4).
# The Oct 3 password is in git history, so it must be changed on the live instance,
# not only removed from the code.
set -euo pipefail

env_file="${1:-$(dirname "$0")/.gitea.env}"
ns="${GITEA_NAMESPACE:-gitea}"
[[ -f "$env_file" ]] || { echo "missing $env_file: run make gitea-env first" >&2; exit 1; }

set -a
# shellcheck disable=SC1090
. "$env_file"
set +a

change() {
  local user="$1" pass="$2"
  kubectl -n "$ns" exec deploy/gitea -- \
    gitea admin user change-password --username "$user" --password "$pass" --must-change-password=false >/dev/null
  echo "rotated $user"
}

change "${GITEA_ADMIN_USER:-gitea_admin}" "$GITEA_ADMIN_PASSWORD"
for repo in frontend payments recommendations platform; do
  var="GITEA_BOT_PASSWORD_$(echo "$repo" | tr '[:lower:]' '[:upper:]')"
  change "${repo}-bot" "${!var}"
done
