#!/usr/bin/env bash
# Bootstrap Gitea admin, org, repos, and per-repo bot users (Plan task B3, Evidence E1, E15).
# Reads passwords from cluster/.gitea.env and creates Kubernetes Secret gitea-credentials.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.gitea.env"
NS="${GITEA_NAMESPACE:-gitea}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Generating fresh .gitea.env credentials..."
  bash "${SCRIPT_DIR}/gen_gitea_env.sh" "$ENV_FILE"
fi

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

echo "============================================================"
echo "Bootstrapping Gitea instance on cluster (namespace: $NS)"
echo "============================================================"

# Ensure Gitea pod is ready
echo "Waiting for Gitea deployment to be available..."
kubectl -n "$NS" rollout status deploy/gitea --timeout=90s

# 1. Ensure admin user exists and password is set
echo "[1/4] Ensuring admin user '${GITEA_ADMIN_USER}'..."
if kubectl -n "$NS" exec deploy/gitea -- gitea admin user list | grep -q "${GITEA_ADMIN_USER}"; then
  kubectl -n "$NS" exec deploy/gitea -- \
    gitea admin user change-password --username "${GITEA_ADMIN_USER}" --password "${GITEA_ADMIN_PASSWORD}" --must-change-password=false >/dev/null
  echo "  Admin password updated."
else
  kubectl -n "$NS" exec deploy/gitea -- \
    gitea admin user create --username "${GITEA_ADMIN_USER}" --password "${GITEA_ADMIN_PASSWORD}" --email "admin@atp.local" --admin --must-change-password=false >/dev/null
  echo "  Admin user created."
fi

# 2. Ensure per-repo bot users exist
echo "[2/4] Ensuring per-repo bot users..."
REPOS=("frontend" "payments" "recommendations" "platform")
for repo in "${REPOS[@]}"; do
  bot="${repo}-bot"
  var="GITEA_BOT_PASSWORD_$(echo "$repo" | tr '[:lower:]' '[:upper:]')"
  pass="${!var}"
  if kubectl -n "$NS" exec deploy/gitea -- gitea admin user list | grep -q "${bot}"; then
    kubectl -n "$NS" exec deploy/gitea -- \
      gitea admin user change-password --username "$bot" --password "$pass" --must-change-password=false >/dev/null
    echo "  Updated $bot."
  else
    kubectl -n "$NS" exec deploy/gitea -- \
      gitea admin user create --username "$bot" --password "$pass" --email "${bot}@atp.local" --must-change-password=false >/dev/null
    echo "  Created $bot."
  fi
done

# 3. Create Kubernetes Secrets for in-cluster access
echo "[3/4] Creating Kubernetes Secret 'gitea-credentials'..."
for target_ns in "$NS" "agents"; do
  kubectl create namespace "$target_ns" --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n "$target_ns" create secret generic gitea-credentials \
    --from-literal=admin-user="${GITEA_ADMIN_USER}" \
    --from-literal=admin-password="${GITEA_ADMIN_PASSWORD}" \
    --from-literal=bot-frontend-password="${GITEA_BOT_PASSWORD_FRONTEND}" \
    --from-literal=bot-payments-password="${GITEA_BOT_PASSWORD_PAYMENTS}" \
    --from-literal=bot-recommendations-password="${GITEA_BOT_PASSWORD_RECOMMENDATIONS}" \
    --from-literal=bot-platform-password="${GITEA_BOT_PASSWORD_PLATFORM}" \
    --dry-run=client -o yaml | kubectl apply -f -
done
echo "  Kubernetes secret 'gitea-credentials' synced to namespaces '$NS' and 'agents'."

# 4. Bootstrap organization and repos via Gitea API or CLI
echo "[4/4] Verifying organization and repositories..."
AUTH_HEADER=$(echo -n "${GITEA_ADMIN_USER}:${GITEA_ADMIN_PASSWORD}" | base64)

# Create online-boutique org if not present
create_org_payload='{"username":"online-boutique","full_name":"Online Boutique Microservices Demo","visibility":"public"}'
kubectl -n "$NS" exec deploy/gitea -- curl -s -k -X POST "http://localhost:3000/api/v1/orgs" \
  -H "Authorization: Basic ${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "$create_org_payload" >/dev/null || true

for repo in "${REPOS[@]}"; do
  create_repo_payload="{\"name\":\"${repo}\",\"description\":\"Online Boutique ${repo} microservice\",\"private\":false,\"auto_init\":true}"
  kubectl -n "$NS" exec deploy/gitea -- curl -s -k -X POST "http://localhost:3000/api/v1/orgs/online-boutique/repos" \
    -H "Authorization: Basic ${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d "$create_repo_payload" >/dev/null || true

  # Add bot as collaborator with write access
  kubectl -n "$NS" exec deploy/gitea -- curl -s -k -X PUT "http://localhost:3000/api/v1/repos/online-boutique/${repo}/collaborators/${repo}-bot" \
    -H "Authorization: Basic ${AUTH_HEADER}" \
    -H "Content-Type: application/json" \
    -d '{"permission":"write"}' >/dev/null || true
  echo "  Repo online-boutique/${repo} ready with collaborator ${repo}-bot."
done

echo "============================================================"
echo "Gitea Bootstrap Complete!"
echo "============================================================"
