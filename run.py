"""Development entry point for Elastic Desk."""

import argparse
import getpass
import json
import os
from pathlib import Path

import uvicorn


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Elastic Desk.")
    parser.add_argument(
        "--fleet-agents-limit",
        type=int,
        default=int(os.getenv("FLEET_AGENTS_LIMIT", "10000")),
        help="Maximum number of Fleet agents to load (default: 10000)",
    )
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--set-ui-password",
        action="store_true",
        help="Interactively set or change the shared UI password, then exit",
    )
    auth_group.add_argument(
        "--disable-ui-auth",
        action="store_true",
        help="Disable UI password authentication, then exit",
    )
    args = parser.parse_args()

    config_path = Path(__file__).parent / "config.json"
    try:
        app_config = json.loads(config_path.read_text())
        if not isinstance(app_config, dict):
            app_config = {}
    except (OSError, ValueError):
        app_config = {}

    if args.set_ui_password:
        from argon2 import PasswordHasher

        password = getpass.getpass("New shared UI password (minimum 12 characters): ")
        confirmation = getpass.getpass("Confirm UI password: ")
        if len(password) < 12:
            parser.error("UI password must be at least 12 characters")
        if password != confirmation:
            parser.error("Passwords do not match")
        app_config["ui_auth"] = {"enabled": True, "password_hash": PasswordHasher().hash(password)}
        config_path.write_text(json.dumps(app_config, ensure_ascii=False, indent=2) + "\n")
        try:
            config_path.chmod(0o600)
        except OSError:
            pass
        print("UI password saved as an Argon2 hash. Restart Elastic Desk to apply it.")
        raise SystemExit(0)

    if args.disable_ui_auth:
        app_config["ui_auth"] = {"enabled": False}
        config_path.write_text(json.dumps(app_config, ensure_ascii=False, indent=2) + "\n")
        try:
            config_path.chmod(0o600)
        except OSError:
            pass
        print("UI password authentication disabled. Restart Elastic Desk to apply it.")
        raise SystemExit(0)

    if args.fleet_agents_limit < 1:
        parser.error("--fleet-agents-limit must be at least 1")
    os.environ["FLEET_AGENTS_LIMIT"] = str(args.fleet_agents_limit)

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "0").lower() in {"1", "true", "yes"},
    )
