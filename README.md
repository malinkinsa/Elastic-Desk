# Elastic Desk

A lightweight, self-hosted web dashboard for monitoring Elasticsearch clusters, inspecting shards, and browsing Elastic Fleet agents.

Elastic Desk is built with FastAPI and a locally vendored Vue 3 runtime. The UI is served directly by the Python application; no Node.js build step or external CDN is required.

## Features

- Cluster health, node roles, shard counts, and data-node disk usage.
- Node grouping and selectable node attributes, plus shard filtering/sorting by size.
- Index and shard search, with a basic Elasticsearch `match` query.
- Shard relocation between nodes with a dry-run preview before applying a move.
- Fleet agent status filters and sorting, plus agent policies and their integrations.
- Automatic refresh every 15 seconds, with a manual refresh control.
- English and Russian UI, plus light, dark, and system appearance modes.
- Optional shared-password UI/API authentication using Argon2 hashes.
- Configurable Elasticsearch TLS verification and custom CA certificates.

## Requirements

- Python 3.13 or newer.
- Access to an Elasticsearch cluster. A Kibana URL is additionally required for Fleet data.

## Quick start

Create a virtual environment and install the project:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

On Windows PowerShell, activate the environment with:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Start the dashboard:

```bash
ES_URL=http://localhost:9200 python run.py
```

Then open <http://127.0.0.1:8000>. On PowerShell, set the environment variable first:

```powershell
$env:ES_URL = "http://localhost:9200"
python run.py
```

If the cluster cannot be reached, the UI offers a connection form. After a successful connection, settings are saved to the local `config.json` file. Do not commit that file: it may contain Elasticsearch credentials.

## Configuration

Values saved in `config.json` take precedence over the corresponding environment variables. Environment variables are used as defaults when a setting has not been saved in the config.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ES_URL` | `http://localhost:9200` | Elasticsearch URL |
| `ES_USERNAME` | — | Elasticsearch username (Basic Auth) |
| `ES_PASSWORD` | — | Elasticsearch password (Basic Auth) |
| `ES_API_KEY` | — | Elasticsearch API key; takes precedence over Basic Auth |
| `KIBANA_URL` | — | Kibana URL for Fleet data |
| `KIBANA_API_KEY` | — | Optional API key for Kibana |
| `HOST` | `127.0.0.1` | Web server bind address |
| `PORT` | `8000` | Web server port |
| `ES_TIMEOUT` | `8` | Elasticsearch/Kibana request timeout in seconds |
| `FLEET_AGENTS_LIMIT` | `10000` | Maximum Fleet agents loaded by the server |
| `RELOAD` | `0` | Set to `1` to enable Uvicorn auto-reload during development |

TLS verification is enabled by default. A CA certificate can be uploaded in the connection form and stored locally as `ca.pem`. Disabling certificate verification is available for troubleshooting, but is not recommended for production.

### Create a least-privilege Elasticsearch API key

For the full dashboard, including shard relocation, create a key with cluster `manage` and index `read`/`monitor` privileges. `manage` includes cluster monitoring and is required by the shard reroute action; it also allows other cluster-management operations, so only use this key with a trusted Elastic Desk deployment. The index privileges allow document search and index/shard metadata reads. To narrow access further, replace `"*"` with the specific index or data-stream patterns the dashboard should access.

The creating Elasticsearch user needs `manage_own_api_key` or `manage_api_key`, and must itself have the privileges being assigned: API-key privileges are intersected with the creator's privileges. Set the connection details in your shell, then run:

```bash
export ES_URL="https://elasticsearch.example.com:9200"
export ES_USERNAME="api-key-admin"
read -s ES_PASSWORD
export ES_PASSWORD

export ES_API_KEY="$(curl --fail-with-body --silent --show-error \
  --user "$ES_USERNAME:$ES_PASSWORD" \
  --header 'Content-Type: application/json' \
  --request POST "$ES_URL/_security/api_key" \
  --data '{
    "name": "elastic-desk",
    "expiration": "90d",
    "role_descriptors": {
      "elastic_desk": {
        "cluster": ["manage"],
        "indices": [
          {
            "names": ["*"],
            "privileges": ["read", "monitor"]
          }
        ]
      }
    }
  }' | jq -er 'if .encoded then .encoded else (.id + ":" + .api_key | @base64) end')"

unset ES_PASSWORD
```

`ES_API_KEY` now contains the encoded key expected by Elastic Desk. Start the app in the same shell with `python run.py` (or `uv run python run.py` if using uv). The dashboard uses saved values from `config.json` before environment variables; if it already has an API key saved, update the connection in the UI or remove that saved value before relying on `ES_API_KEY`.

If shard relocation is not needed, omit the `manage` cluster privilege and use `"cluster": ["monitor"]` instead. This read-only variant still supports cluster/node monitoring, index/shard listings, and search, but cannot move shards. See Elastic's [privilege reference](https://www.elastic.co/docs/reference/elasticsearch/security-privileges) and [Create API key API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key) for details.

### Use a dedicated Elasticsearch user instead

If you prefer Basic Auth over an API key, create a dedicated role and user. The admin account used below needs the `manage_security` cluster privilege to manage roles and users. Use a strong unique password, and replace `"*"` with narrower index/data-stream patterns where possible.

```bash
export ES_URL="https://elasticsearch.example.com:9200"
export ES_ADMIN_USERNAME="elastic"
read -s ES_ADMIN_PASSWORD
export ES_ADMIN_PASSWORD
read -s ELASTIC_DESK_PASSWORD
export ELASTIC_DESK_PASSWORD

curl --fail-with-body --silent --show-error \
  --user "$ES_ADMIN_USERNAME:$ES_ADMIN_PASSWORD" \
  --header 'Content-Type: application/json' \
  --request PUT "$ES_URL/_security/role/elastic_desk" \
  --data '{
    "cluster": ["manage"],
    "indices": [
      {
        "names": ["*"],
        "privileges": ["read", "monitor"]
      }
    ]
  }'

curl --fail-with-body --silent --show-error \
  --user "$ES_ADMIN_USERNAME:$ES_ADMIN_PASSWORD" \
  --header 'Content-Type: application/json' \
  --request POST "$ES_URL/_security/user/elastic_desk_test" \
  --data "$(jq -n --arg password "$ELASTIC_DESK_PASSWORD" \
    '{password:$password, roles:["elastic_desk"], full_name:"Elastic Desk test user"}')"

export ES_USERNAME="elastic_desk_test"
export ES_PASSWORD="$ELASTIC_DESK_PASSWORD"
unset ES_ADMIN_PASSWORD ELASTIC_DESK_PASSWORD
python run.py
```

The user can now be entered in the connection form or supplied via `ES_USERNAME` and `ES_PASSWORD`. This role has the same access as the full-featured API key above, including shard relocation. For a read-only user, change its role's cluster privileges from `manage` to `monitor`; shard moves will then be unavailable. See Elastic's [Create or update roles API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/operation/operation-security-put-role) and [Create or update users API](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-put-user).

### Fleet

Set `KIBANA_URL` or enter the URL on the Fleet tab. By default, Fleet requests use the Elasticsearch credentials. Set `KIBANA_API_KEY` when Kibana requires a separate API key. The agent list is capped by `FLEET_AGENTS_LIMIT`; the startup option `--fleet-agents-limit` can override it:

```bash
python run.py --fleet-agents-limit 5000
```

## Optional UI authentication

For a local installation, set or change the shared UI password interactively:

```bash
python run.py --set-ui-password
```

Enter a password of at least 12 characters twice. Only its Argon2 hash is written to `config.json`. Restart the application to apply the setting. To disable authentication:

```bash
python run.py --disable-ui-auth
```

Authentication protects the UI API and the interactive API documentation. It uses a shared password (not individual user accounts) and an HttpOnly, SameSite cookie with a 12-hour session lifetime. Login attempts are rate-limited. If the dashboard is reachable from other machines, put it behind an HTTPS reverse proxy.

The config setting is:

```json
{
  "ui_auth": {
    "enabled": true,
    "password_hash": "$argon2id$..."
  }
}
```

For container deployments, the environment variables below override the config values. When authentication is enabled, provide a hash either through the environment or a mounted config file; the application refuses to start without one.

| Variable | Purpose |
| --- | --- |
| `UI_AUTH_ENABLED` | Explicitly enable or disable UI authentication (`true`/`false`; overrides `ui_auth.enabled`) |
| `UI_AUTH_PASSWORD_HASH` | Argon2 password hash (overrides `ui_auth.password_hash`) |

The repository does not currently include a Dockerfile or Compose file; these variables are provided for deployments that package the application in a container.

## API overview

The UI uses the following application endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/cluster` | Cluster health |
| `GET /api/nodes` | Node roles, selectable node attributes, resource stats, and disk usage |
| `GET /api/indices` | Index summary |
| `GET /api/shards` | Shard list and sizes |
| `POST /api/search` | Search an index with a `match` query |
| `GET /api/fleet` | Fleet agents and agent policies from Kibana |
| `POST /api/shards/move/preview` | Validate a proposed shard relocation without applying it |
| `POST /api/shards/move/apply` | Apply the selected shard relocation |

When UI authentication is enabled, these endpoints require an authenticated session.

## Development

Run the application with auto-reload enabled:

```bash
RELOAD=1 python run.py
```

The backend is in `main.py`; `run.py` is the development/startup entry point. The Vue UI, translations, icons, and vendored runtime are under `static/`. Add or update UI strings in both `static/locales/en.js` and `static/locales/ru.js`.

To run a syntax check for the Python modules:

```bash
python -m compileall main.py run.py
```

## Project structure

```text
.
├── main.py                 # FastAPI application and Elasticsearch/Kibana API
├── run.py                  # Startup options and local UI-password management
├── pyproject.toml          # Python project metadata and dependencies
├── static/
│   ├── index.html          # Vue application and styles
│   ├── locales/            # Translations
│   ├── icons/              # Local SVG assets
│   └── vendor/             # Vendored Vue runtime and its license
└── README.md
```
