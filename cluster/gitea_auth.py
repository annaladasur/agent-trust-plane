"""Gitea credentials for the lab scripts, read from the environment.

Plan task A4 (Evidence E16): no password lives in code. Each account has its own value:
  GITEA_ADMIN_USER           admin login (default gitea_admin)
  GITEA_ADMIN_PASSWORD       admin password
  GITEA_BOT_USER             bot login override (default <repo>-bot)
  GITEA_BOT_PASSWORD_<REPO>  one password per repo bot, e.g. GITEA_BOT_PASSWORD_FRONTEND

Generate them once with `make gitea-env` (writes cluster/.gitea.env, which git ignores),
apply them to the running Gitea with `make gitea-rotate`, and load them before running a
script by hand:  set -a; . cluster/.gitea.env; set +a
The Make targets load the file for you.
"""

import base64
import os
import sys


# Automatically load cluster/.gitea.env if present
_env_path = os.path.join(os.path.dirname(__file__), ".gitea.env")
if os.path.isfile(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())


def _require(var: str) -> str:
    value = os.environ.get(var)
    if not value:
        sys.exit(
            f"error: {var} is not set. Run `make gitea-env` or set {var} in your environment "
            "(see cluster/gitea_auth.py)."
        )
    return value


def basic_auth(user: str, password: str) -> str:
    return base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")


def admin_auth() -> str:
    user = os.environ.get("GITEA_ADMIN_USER", "gitea_admin")
    return basic_auth(user, _require("GITEA_ADMIN_PASSWORD"))


def bot_auth(repo: str) -> str:
    user = os.environ.get("GITEA_BOT_USER", f"{repo}-bot")
    return basic_auth(user, _require(f"GITEA_BOT_PASSWORD_{repo.upper().replace('-', '_')}"))
