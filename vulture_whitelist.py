"""Vulture whitelist — symbols that are used but not detectable by static analysis.

Vulture cannot follow framework dispatch, so these legitimate symbols are
whitelisted here. Entries are grouped by reason. CI runs::

    vulture --min-confidence 60 src/openhands/ev2 vulture_whitelist.py

Review this file when adding/removing code: each entry must remain justified.

FastAPI route handlers, Pydantic validators/serializers, and SQLAlchemy
TypeDecorator hooks are excluded via ``[tool.vulture]`` ignore patterns in
pyproject.toml and do *not* need to appear here.
"""

# ---- Enum members (serialized to/from DB columns and JSON) ----
AUTOMATIC
DEACTIVATING
DELETING
REFRESH_TOKEN
SNAPSHOTTING

# ---- SQLAlchemy ORM columns (mapped, read/written via ORM, not by name) ----
accumulated_cost
cache_read_tokens
cache_write_tokens
completion_tokens
context_window
cwd
email_verified
feature_flag
icon
invocations
keep_alive
members
per_turn_token
preferred_username
prompt_tokens
provider_connection
reasoning_tokens
refresh_token_expires_at
replaced_by
role_overrides
sandbox_configs
sandbox_template
session_api_key
sse_read_timeout
status_detail
total_duration_ms
transport
user_overrides

# ---- Role per-entity permission columns (AGENTS.md §11; copied generically) ----
api_key_permission
cors_origin_permission
feature_flag_permission
feature_flag_role_assignment_permission
feature_flag_user_assignment_permission
group_permission
group_user_permission
llm_aggregated_usage_permission
llm_permission
mcp_aggregated_usage_permission
mcp_server_config_permission
oauth_client_permission
provider_connection_permission
role_permission
sandbox_permission
sandbox_snapshot_permission
sandbox_template_permission
secret_permission
secret_value_permission
user_permission
user_role_permission

# ---- Classes registered via import side-effect / introspection ----
AccessToken
CreatorPermission
GroupPermission
OAuthClientSearchFilter
ReadOnly
RefreshToken
SecretValueAccess
# Selected dynamically via the `secrets_service_class` config FQCN.
SqlSecretsService

# ---- Pydantic request/response schemas (serialized by FastAPI; not called) ----
AuthorizeRequest
LoginResponse
UserLogin

# ---- Type used only in a string annotation (cast("CursorResult[Any]", ...)) ----
CursorResult

# ---- Tested utility functions / methods (reached via tests, not src dispatch) ----
AttributeFilter
create_auth_token
dispose_engine_factory
extract_user_id
list_snapshot_ids
mcp_proxy_url_for
or_filter
reset_engine_factory
snapshot_created_at

# ---- Auth token / service methods (called via tests + routes) ----
_.create_access_token
_.create_refresh_token
_.get_client
_.mint_session_cookie
_.reissue_cookie
_.search_clients

# ---- Sandbox template helper (called via _dicts_to_exposed_ports wrapper) ----
_.to_exposed_ports

# ---- Encryption: JWS verification exercised by tests ----
_.verify_jws_token
