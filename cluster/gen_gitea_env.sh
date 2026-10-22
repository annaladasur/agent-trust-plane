#!/usr/bin/env bash
# Generate fresh Gitea credentials for the lab into cluster/.gitea.env (git-ignored).
# One random password per account: the admin and each repo bot (plan task A4, Evidence E16).
# Then run `make gitea-rotate` to set them on the running Gitea.
set -euo pipefail

out="${1:-$(dirname "$0")/.gitea.env}"
if [[ -e "$out" ]]; then
  echo "$out already exists. Delete it first to generate new values." >&2
  exit 1
fi

umask 077
rand() { openssl rand -base64 32 | tr -d '/+=\n' | cut -c1-28; }

{
  echo "# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) by cluster/gen_gitea_env.sh. Never commit this file."
  echo "GITEA_ADMIN_USER=gitea_admin"
  echo "GITEA_ADMIN_PASSWORD=$(rand)"
  for repo in frontend payments recommendations platform; do
    echo "GITEA_BOT_PASSWORD_$(echo "$repo" | tr '[:lower:]' '[:upper:]')=$(rand)"
  done
} > "$out"

echo "wrote $out (mode 600)"
