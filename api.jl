# api.jl
# JWT API Authentication Demo (Oxygen.jl)

using Oxygen
using HTTP
using Dates
using SHA
using JSON3
using StructTypes
using JSONWebTokens
using LibPQ
using LibPQ: columntable

####################################
# CONFIGURATION                    #
####################################

const DB_HOST = get(ENV, "DB_HOST", "localhost")
const DB_PORT = get(ENV, "DB_PORT", "5432")
const DB_NAME = get(ENV, "DB_NAME", "jwt_api_db")
const DB_USER = get(ENV, "DB_USER", "api_user")
const DB_PASSWORD = get(ENV, "DB_PASSWORD", "password")

const JWT_SECRET = get(ENV, "JWT_SECRET", "change-me-in-production")
const API_PORT = parse(Int, get(ENV, "API_PORT", "8080"))

# Demo latch (admin endpoints disabled unless true)
const DEMO_UNSAFE_ADMIN = lowercase(get(ENV, "DEMO_UNSAFE_ADMIN", "true")) == "true"

const DB_CONN_STRING = "host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER password=$DB_PASSWORD"

println("DB: host=$(DB_HOST) port=$(DB_PORT) dbname=$(DB_NAME) user=$(DB_USER)")

# Global DB connection (demo). Production: pool/PgBouncer.
DB_CONN = nothing

####################################
# TIME UTILITIES (UTC)             #
####################################

utcnow() = Dates.now(Dates.UTC)

function unix2datetime_utc(unix_seconds::Real)
    return Dates.unix2datetime(unix_seconds) # treat as UTC in demo
end

"""
Normalize expires_in_days from request JSON.

Accepts:
- missing field -> default_days
- JSON null -> nothing (indefinite)
- integer -> Int
- string -> parsed Int
- 0 or negative -> nothing (indefinite)
"""
function normalize_expires_in_days(body; default_days::Int=365)::Union{Int,Nothing}
    expires_raw = get(body, :expires_in_days, get(body, "expires_in_days", default_days))

    expires_in_days::Union{Int,Nothing} = if expires_raw isa JSON3.Null
        nothing
    elseif expires_raw === nothing
        nothing
    elseif expires_raw isa Integer
        Int(expires_raw)
    elseif expires_raw isa AbstractString
        s = strip(expires_raw)
        isempty(s) ? nothing : parse(Int, s)
    else
        default_days
    end

    # Treat 0 or negative as "no expiry"
    if expires_in_days !== nothing && expires_in_days <= 0
        return nothing
    end

    return expires_in_days
end


####################################
# DB CONNECTION                    #
####################################

function init_db_connection()
    max_retries = 5
    retry_delay = 2

    for attempt in 1:max_retries
        try
            println("Connecting to database (attempt $attempt/$max_retries)...")
            global DB_CONN = LibPQ.Connection(DB_CONN_STRING)
            println("Database connected successfully!")
            return true
        catch e
            println("Database connection failed: $e")
            if attempt < max_retries
                println("Retrying in $retry_delay seconds...")
                sleep(retry_delay)
            else
                println("Failed to connect to database after $max_retries attempts")
                return false
            end
        end
    end
    return false
end

atexit(() -> begin
    if DB_CONN !== nothing
        try
            close(DB_CONN)
        catch
            # ignore
        end
    end
end)

####################################
# REQUEST TYPES (Swagger schema)   #
####################################

Base.@kwdef struct IssueTokenRequest
    client_id::String
    client_name::String
    expires_in_days::Union{Int,Nothing} = 365
end
StructTypes.StructType(::Type{IssueTokenRequest}) = StructTypes.Struct()

####################################
# SECURITY UTILITIES               #
####################################

hash_token(token::String) = bytes2hex(sha256(token))

function getheader(headers, key::AbstractString, default="")
    for (k, v) in headers
        if lowercase(String(k)) == lowercase(key)
            return v
        end
    end
    return default
end

function get_client_ip(req::HTTP.Request)
    xff = getheader(req.headers, "X-Forwarded-For", "")
    if !isempty(xff)
        return strip(split(xff, ",")[1])
    end
    xri = getheader(req.headers, "X-Real-IP", "")
    return isempty(xri) ? "unknown" : xri
end

function merge_context!(req::HTTP.Request, additions::Dict{Symbol,Any})
    if req.context === nothing
        req.context = Dict{Symbol,Any}()
    end

    if !(req.context isa Dict{Symbol,Any})
        ctx = Dict{Symbol,Any}()
        for (k, v) in req.context
            if k isa Symbol
                ctx[k] = v
            else
                ctx[Symbol(String(k))] = v
            end
        end
        req.context = ctx
    end

    for (k, v) in additions
        req.context[k] = v
    end
end


function get_client_info(req::HTTP.Request)
    ctx = req.context
    if ctx === nothing
        return nothing
    end

    # support either symbol-key or string-key contexts (defensive)
    if haskey(ctx, :client_id)
        return Dict("client_id" => ctx[:client_id], "client_name" => ctx[:client_name])
    elseif haskey(ctx, "client_id")
        return Dict("client_id" => ctx["client_id"], "client_name" => ctx["client_name"])
    end

    return nothing
end


####################################
# RATE LIMITING (DEMO)             #
####################################

const RATE_LIMIT_STORE = Dict{String, Vector{Float64}}()
const RATE_LIMIT_WINDOW = 60.0
const RATE_LIMIT_MAX_REQUESTS = 100
const RL_LOCK = ReentrantLock()

function check_rate_limit(client_id::String)
    nowt = time()
    lock(RL_LOCK)
    try
        if !haskey(RATE_LIMIT_STORE, client_id)
            RATE_LIMIT_STORE[client_id] = Float64[]
        end
        filter!(t -> (nowt - t) < RATE_LIMIT_WINDOW, RATE_LIMIT_STORE[client_id])

        if length(RATE_LIMIT_STORE[client_id]) >= RATE_LIMIT_MAX_REQUESTS
            return false, 0, RATE_LIMIT_WINDOW
        end

        push!(RATE_LIMIT_STORE[client_id], nowt)
        remaining = RATE_LIMIT_MAX_REQUESTS - length(RATE_LIMIT_STORE[client_id])
        return true, remaining, RATE_LIMIT_WINDOW
    finally
        unlock(RL_LOCK)
    end
end

####################################
# DATABASE FUNCTIONS               #
####################################

function save_token_to_db(client_id::String, client_name::String, token::String,
                          expires_at::Union{DateTime,Nothing}, created_by::String)

    token_hash = hash_token(token)

    if expires_at === nothing
        query = """
            INSERT INTO api_tokens
            (client_id, client_name, token_hash, expires_at, created_by, active)
            VALUES (\$1, \$2, \$3, NULL, \$4, true)
            ON CONFLICT (client_id)
            DO UPDATE SET
                token_hash = EXCLUDED.token_hash,
                expires_at = NULL,
                issued_at = NOW(),
                active = true,
                created_by = EXCLUDED.created_by
            RETURNING id
        """
        return execute(DB_CONN, query, [client_id, client_name, token_hash, created_by])
    else
        query = """
            INSERT INTO api_tokens
            (client_id, client_name, token_hash, expires_at, created_by, active)
            VALUES (\$1, \$2, \$3, NULL, \$4, true)
            ON CONFLICT (client_id)
            DO UPDATE SET
                token_hash = EXCLUDED.token_hash,
                expires_at = EXCLUDED.expires_at,
                issued_at = NOW(),
                active = true,
                created_by = EXCLUDED.created_by
            RETURNING id
        """
        return execute(DB_CONN, query, [client_id, client_name, token_hash, expires_at, created_by])
    end
end


function revoke_token(client_id::String)
    query = """
        UPDATE api_tokens
        SET active = false
        WHERE client_id = \$1
        RETURNING client_id
    """
    result = execute(DB_CONN, query, [client_id])
    return LibPQ.num_rows(result) > 0
end

function hard_delete_token(client_id::String)::Bool
    result = execute(DB_CONN, "DELETE FROM api_tokens WHERE client_id = \$1 RETURNING client_id", [client_id])
    return LibPQ.num_rows(result) > 0
end

function get_all_tokens()
    query = """
        SELECT
            client_id, client_name, active,
            issued_at, expires_at, last_used_at, created_by
        FROM api_tokens
        ORDER BY issued_at DESC
    """
    result = execute(DB_CONN, query)
    if LibPQ.num_rows(result) == 0
        return []
    end
    data = columntable(result)

    return [
        Dict(
            "client_id" => data.client_id[i],
            "client_name" => data.client_name[i],
            "active" => data.active[i],
            "issued_at" => string(data.issued_at[i]),
            "expires_at" => ismissing(data.expires_at[i]) ? nothing : string(data.expires_at[i]),
            "last_used_at" => ismissing(data.last_used_at[i]) ? nothing : string(data.last_used_at[i]),
            "created_by" => data.created_by[i]
        ) for i in 1:length(data.client_id)
    ]
end

function log_token_usage(client_id::String, endpoint::String, method::String,
                         status_code::Int, ip_address::String="unknown")
    query = """
        INSERT INTO token_usage_log (client_id, endpoint, method, status_code, ip_address)
        VALUES (\$1, \$2, \$3, \$4, \$5)
    """
    try
        execute(DB_CONN, query, [client_id, endpoint, method, status_code, ip_address])
    catch e
        @error "Failed to log usage" exception=e
    end
end

####################################
# JWT FUNCTIONS                    #
####################################

# Normalize expires_in_days coming from JSON (supports null and 0)
function normalize_expires_in_days(body)::Union{Int,Nothing}
    raw = get(body, :expires_in_days, get(body, "expires_in_days", 365))

    if raw === nothing
        return nothing
    end

    if raw isa Integer
        v = Int(raw)
        return v <= 0 ? nothing : v
    end

    if raw isa Real
        v = Int(round(raw))
        return v <= 0 ? nothing : v
    end

    s = strip(string(raw))
    if isempty(s)
        return 365
    end
    v = parse(Int, s)
    return v <= 0 ? nothing : v
end

function generate_api_jwt(client_id::String; expires_in_days::Union{Int,Nothing}=365)
    now_unix = Int(floor(time()))  # integer seconds

    claims = Dict(
        "sub"  => client_id,
        "type" => "api_access",
        "iat"  => now_unix,
        "iss"  => "jwt-api-server"
    )

    expires_at = nothing
    if expires_in_days !== nothing
        exp_unix = now_unix + (expires_in_days * 86400)  # still Int
        claims["exp"] = exp_unix
        expires_at = Dates.unix2datetime(exp_unix)        # safe now
    else
        # if you still want "indefinite", you can either:
        # A) omit exp entirely (requires you to stop enforcing exp in validate_api_jwt), OR
        # B) set far-future exp but keep DB expires_at as NULL
        exp_unix = now_unix + (3650 * 86400)  # 10 years
        claims["exp"] = exp_unix
        expires_at = nothing  # DB “never expires”
    end

    encoding = JSONWebTokens.HS256(JWT_SECRET)
    token = JSONWebTokens.encode(encoding, claims)
    return token, expires_at
end

function validate_api_jwt(token::AbstractString)
    try
        token_s = String(token)

        encoding = JSONWebTokens.HS256(JWT_SECRET)
        claims = JSONWebTokens.decode(encoding, token_s)

        if haskey(claims, "exp") && Float64(claims["exp"]) < time()
            return nothing
        end
        if get(claims, "type", "") != "api_access"
            return nothing
        end

        db_info = validate_token_in_db(token_s)
        db_info === nothing && return nothing

        return merge(Dict{String,Any}(pairs(claims)), db_info)
    catch
        return nothing
    end
end


function validate_token_in_db(token::AbstractString)
    token_s = String(token)
    token_hash = hash_token(token_s)

    result = execute(DB_CONN, """
        SELECT client_id, client_name, expires_at, active
        FROM api_tokens
        WHERE token_hash = \$1
    """, [token_hash])

    LibPQ.num_rows(result) == 0 && return nothing

    data = columntable(result)
    client_id   = String(data.client_id[1])
    client_name = String(data.client_name[1])
    expires_at  = data.expires_at[1]
    active      = data.active[1]

    active == true || return nothing

    if !(ismissing(expires_at) || expires_at === nothing)
        if expires_at < utcnow()
            return nothing
        end
    end


    execute(DB_CONN, "UPDATE api_tokens SET last_used_at = NOW() WHERE token_hash = \$1", [token_hash])

    return Dict("client_id" => client_id, "client_name" => client_name)
end

####################################
# MIDDLEWARE                       #
####################################

const UNPROTECTED_PREFIXES = ("/health", "/docs", "/openapi", "/swagger")

function JWTAuthMiddleware(handler)
    return function(req::HTTP.Request)
        for prefix in UNPROTECTED_PREFIXES
            if startswith(req.target, prefix)
                return handler(req)
            end
        end

        # /admin/* unprotected in demo (but latched)
        if startswith(req.target, "/admin")
            if !DEMO_UNSAFE_ADMIN
                return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
                    "error" => "admin_disabled",
                    "error_description" => "Admin endpoints are disabled. Set DEMO_UNSAFE_ADMIN=true for demo mode."
                )))
            end
            return handler(req)
        end

        # /api/* requires Bearer
        auth_header = getheader(req.headers, "Authorization", "")
        if isempty(auth_header) || !startswith(auth_header, "Bearer ")
            return HTTP.Response(401, [
                "Content-Type" => "application/json",
                "WWW-Authenticate" => "Bearer realm=\"API\""
            ], JSON3.write(Dict(
                "error" => "missing_or_invalid_token",
                "error_description" => "Authorization header must be: Bearer <token>"
            )))
        end

        token = strip(replace(auth_header, "Bearer " => "", count=1))
        claims = validate_api_jwt(token)
        if claims === nothing
            return HTTP.Response(401, [
                "Content-Type" => "application/json",
                "WWW-Authenticate" => "Bearer realm=\"API\", error=\"invalid_token\""
            ], JSON3.write(Dict(
                "error" => "invalid_token",
                "error_description" => "Token is invalid, expired, or revoked"
            )))
        end

        client_id = claims["client_id"]
        client_name = claims["client_name"]

        allowed, remaining, window = check_rate_limit(client_id)
        if !allowed
            return HTTP.Response(429, [
                "Content-Type" => "application/json",
                "X-RateLimit-Limit" => string(RATE_LIMIT_MAX_REQUESTS),
                "X-RateLimit-Remaining" => "0",
                "X-RateLimit-Reset" => string(floor(Int, time() + window)),
                "Retry-After" => string(floor(Int, window))
            ], JSON3.write(Dict(
                "error" => "rate_limit_exceeded",
                "error_description" => "Too many requests. Limit: $RATE_LIMIT_MAX_REQUESTS per $(Int(window)) seconds"
            )))
        end

        ip = get_client_ip(req)

        merge_context!(req, Dict{Symbol,Any}(
            :client_id => client_id,
            :client_name => client_name,
            :ip_address => ip,
            :authenticated => true
        ))


        resp = handler(req)

        if resp isa HTTP.Response
            push!(resp.headers,
                "X-RateLimit-Limit" => string(RATE_LIMIT_MAX_REQUESTS),
                "X-RateLimit-Remaining" => string(remaining),
                "X-RateLimit-Reset" => string(floor(Int, time() + window))
            )
        end


        status = resp isa HTTP.Response ? resp.status : 200
        @async log_token_usage(client_id, req.target, req.method, status, ip)

        return resp
    end
end

####################################
# ROUTES                           #
####################################

@get "/health" function()
    db_status = try
        execute(DB_CONN, "SELECT 1")
        "connected"
    catch
        "disconnected"
    end

    return Dict(
        "status" => "ok",
        "timestamp_utc" => string(utcnow()),
        "database" => db_status,
        "demo_unsafe_admin" => DEMO_UNSAFE_ADMIN
    )
end

@post "/admin/issue-token" function(req::HTTP.Request)
    if !DEMO_UNSAFE_ADMIN
        return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "admin_disabled",
            "error_description" => "Set DEMO_UNSAFE_ADMIN=true to use demo admin endpoints."
        )))
    end

    body = try
        JSON3.read(req.body)
    catch
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "invalid_json",
            "error_description" => "Request body must be valid JSON"
        )))
    end

    client_id = string(get(body, :client_id, get(body, "client_id", "")))
    client_name = string(get(body, :client_name, get(body, "client_name", "")))
    expires_in_days = normalize_expires_in_days(body)  # now supports null + 0

    if isempty(client_id) || isempty(client_name)
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "validation_error",
            "error_description" => "client_id and client_name are required"
        )))
    end

    token, expires_at = generate_api_jwt(client_id, expires_in_days=expires_in_days)

    created_by = "demo-admin"
    save_token_to_db(client_id, client_name, token, expires_at, created_by)

    return HTTP.Response(200, ["Content-Type" => "application/json"], JSON3.write(Dict(
        "success" => true,
        "client_id" => client_id,
        "client_name" => client_name,
        "token" => token,
        "token_type" => "Bearer",
        "expires_in_days" => expires_in_days,
        "expires_at_utc" => expires_at === nothing ? nothing : string(expires_at),
        "usage" => "Authorization: Bearer <token>"
    )))
end

@get "/admin/tokens" function()
    if !DEMO_UNSAFE_ADMIN
        return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "admin_disabled",
            "error_description" => "Set DEMO_UNSAFE_ADMIN=true to use demo admin endpoints."
        )))
    end
    return Dict("tokens" => get_all_tokens())
end

@patch "/admin/tokens/:client_id/revoke" function(req::HTTP.Request, client_id::String)
    if !DEMO_UNSAFE_ADMIN
        return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "admin_disabled",
            "error_description" => "Set DEMO_UNSAFE_ADMIN=true to use demo admin endpoints."
        )))
    end

    revoked = revoke_token(client_id)
    if revoked
        return Dict("success" => true, "message" => "Token revoked", "client_id" => client_id)
    end
    return HTTP.Response(404, ["Content-Type" => "application/json"], JSON3.write(Dict(
        "error" => "not_found",
        "error_description" => "Token not found"
    )))
end

@delete "/admin/tokens/:client_id" function(req::HTTP.Request, client_id::String)
    if !DEMO_UNSAFE_ADMIN
        return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "admin_disabled",
            "error_description" => "Set DEMO_UNSAFE_ADMIN=true to use demo admin endpoints."
        )))
    end

    deleted = hard_delete_token(client_id)
    if deleted
        return Dict("success" => true, "message" => "Token deleted", "client_id" => client_id)
    end

    return HTTP.Response(404, ["Content-Type" => "application/json"], JSON3.write(Dict(
        "error" => "not_found",
        "error_description" => "Token not found"
    )))
end

@get "/admin/usage/:client_id" function(req::HTTP.Request, client_id::String)
    if !DEMO_UNSAFE_ADMIN
        return HTTP.Response(403, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "admin_disabled",
            "error_description" => "Set DEMO_UNSAFE_ADMIN=true to use demo admin endpoints."
        )))
    end

    query = """
        SELECT DATE(timestamp) as date,
               COUNT(*) as request_count,
               COUNT(DISTINCT endpoint) as unique_endpoints
        FROM token_usage_log
        WHERE client_id = \$1
          AND timestamp > NOW() - INTERVAL '30 days'
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
    """

    result = execute(DB_CONN, query, [client_id])
    if LibPQ.num_rows(result) == 0
        return Dict("client_id" => client_id, "usage" => [])
    end

    data = columntable(result)
    usage = [
        Dict(
            "date" => string(data.date[i]),
            "request_count" => data.request_count[i],
            "unique_endpoints" => data.unique_endpoints[i]
        ) for i in 1:length(data.date)
    ]
    return Dict("client_id" => client_id, "usage" => usage)
end

@get "/api/data" function(req::HTTP.Request)
    client = get_client_info(req)
    data = [
        Dict("id" => 1, "value" => "Item 1", "owner" => client["client_id"]),
        Dict("id" => 2, "value" => "Item 2", "owner" => client["client_id"])
    ]
    return Dict("success" => true, "data" => data, "client" => client)
end

@post "/api/data" function(req::HTTP.Request)
    client = get_client_info(req)

    body = try
        JSON3.read(req.body)
    catch
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "invalid_json",
            "error_description" => "Request body must be valid JSON",
            "client" => client
        )))
    end

    has_value = haskey(body, :value) || haskey(body, "value")
    if !has_value
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "validation_error",
            "error_description" => "Missing required field: value",
            "client" => client
        )))
    end

    value = get(body, :value, get(body, "value", nothing))
    if value === nothing || (value isa String && isempty(strip(value)))
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "validation_error",
            "error_description" => "Field value cannot be empty",
            "client" => client
        )))
    end

    resource_id = rand(1000:9999)

    return HTTP.Response(201, [
        "Content-Type" => "application/json",
        "Location" => "/api/data/$resource_id"
    ], JSON3.write(Dict(
        "success" => true,
        "resource" => Dict(
            "id" => resource_id,
            "value" => value,
            "owner" => client["client_id"],
            "created_at_utc" => string(utcnow())
        ),
        "client" => client
    )))
end

@get "/api/data/:id" function(req::HTTP.Request, id::String)
    client = get_client_info(req)
    rid = try
        parse(Int, id)
    catch
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "invalid_id",
            "error_description" => "Resource ID must be a valid integer",
            "client" => client
        )))
    end

    return Dict(
        "success" => true,
        "resource" => Dict(
            "id" => rid,
            "value" => "Sample data for resource $rid",
            "owner" => client["client_id"],
            "created_at_utc" => "2026-01-14T10:00:00Z"
        ),
        "client" => client
    )
end

@delete "/api/data/:id" function(req::HTTP.Request, id::String)
    client = get_client_info(req)
    rid = try
        parse(Int, id)
    catch
        return HTTP.Response(400, ["Content-Type" => "application/json"], JSON3.write(Dict(
            "error" => "invalid_id",
            "error_description" => "Resource ID must be a valid integer",
            "client" => client
        )))
    end

    return Dict("success" => true, "message" => "Resource deleted", "resource_id" => rid, "client" => client)
end

####################################
# SWAGGER / OPENAPI                #
####################################

function setup_swagger_docs()
    mergeschema(Dict(
        "openapi" => "3.0.0",
        "info" => Dict(
            "title" => "JWT API Authentication Demo (Oxygen.jl)",
            "version" => "1.0.0",
            "description" => """
Demonstrates API authentication best practices using JWT bearer tokens.

Demo behavior:
- /admin/* is intentionally unprotected so you can issue/revoke tokens in Swagger.
- /api/* requires Bearer JWT and performs DB revocation checks.

Testing flow:
1) POST /admin/issue-token
2) Click Authorize and paste the token (no quotes)
3) Call /api/* endpoints
            """
        ),
        "servers" => [Dict("url" => "http://localhost:8080", "description" => "Local")]
    ))

    # Components: schemas + bearer auth
    mergeschema(Dict(
        "components" => Dict(
            "schemas" => Dict(
                "IssueTokenRequest" => Dict(
                    "type" => "object",
                    "required" => ["client_id", "client_name"],
                    "properties" => Dict(
                        "client_id" => Dict("type" => "string", "example" => "demo-app"),
                        "client_name" => Dict("type" => "string", "example" => "Demo Application"),
                        "expires_in_days" => Dict(
                            "type" => "integer",
                            "default" => 365,
                            "example" => 30,
                            "description" => "Use null or 0 for a DB-non-expiring token (JWT exp is far-future)."
                        )
                    )
                )
            ),
            "securitySchemes" => Dict(
                "bearerAuth" => Dict(
                    "type" => "http",
                    "scheme" => "bearer",
                    "bearerFormat" => "JWT"
                )
            )
        )
    ))

    mergeschema("/health", Dict(
        "get" => Dict(
            "tags" => ["System"],
            "summary" => "Health check",
            "security" => Any[]
        )
    ))

    # IMPORTANT: OpenAPI path params use {client_id} (not :client_id)
    mergeschema("/admin/issue-token", Dict(
        "post" => Dict(
            "operationId" => "issueToken",
            "tags" => ["Admin - Token Management"],
            "summary" => "Issue a new API token",
            "security" => Any[],
            "requestBody" => Dict(
                "required" => true,
                "content" => Dict(
                    "application/json" => Dict(
                        "schema" => Dict("\$ref" => "#/components/schemas/IssueTokenRequest")
                    )
                )
            ),
            "responses" => Dict(
                "200" => Dict("description" => "Token issued successfully"),
                "400" => Dict("description" => "Validation error"),
                "403" => Dict("description" => "Admin endpoints disabled"),
                "500" => Dict("description" => "Server error")
            )
        )
    ))

    mergeschema("/admin/tokens", Dict(
        "get" => Dict(
            "tags" => ["Admin - Token Management"],
            "summary" => "List tokens (demo admin)",
            "security" => Any[]
        )
    ))

    mergeschema("/admin/tokens/{client_id}/revoke", Dict(
        "patch" => Dict(
            "tags" => ["Admin - Token Management"],
            "summary" => "Revoke token (soft disable)",
            "security" => Any[],
            "parameters" => [
                Dict("name" => "client_id", "in" => "path", "required" => true, "schema" => Dict("type" => "string"))
            ]
        )
    ))

    mergeschema("/admin/tokens/{client_id}", Dict(
        "delete" => Dict(
            "tags" => ["Admin - Token Management"],
            "summary" => "Hard delete token record (demo-only)",
            "security" => Any[],
            "parameters" => [
                Dict("name" => "client_id", "in" => "path", "required" => true, "schema" => Dict("type" => "string"))
            ]
        )
    ))

    mergeschema("/admin/usage/{client_id}", Dict(
        "get" => Dict(
            "tags" => ["Admin - Token Management"],
            "summary" => "Usage stats (demo admin)",
            "security" => Any[],
            "parameters" => [
                Dict("name" => "client_id", "in" => "path", "required" => true, "schema" => Dict("type" => "string"))
            ]
        )
    ))

    mergeschema("/api/data", Dict(
        "get" => Dict(
            "tags" => ["Protected API"],
            "summary" => "Get data (protected)",
            "security" => [Dict("bearerAuth" => [])]
        ),
        "post" => Dict(
            "tags" => ["Protected API"],
            "summary" => "Create data (protected)",
            "security" => [Dict("bearerAuth" => [])]
        )
    ))

    mergeschema("/api/data/{id}", Dict(
        "get" => Dict(
            "tags" => ["Protected API"],
            "summary" => "Get item (protected)",
            "security" => [Dict("bearerAuth" => [])],
            "parameters" => [
                Dict("name" => "id", "in" => "path", "required" => true, "schema" => Dict("type" => "string"))
            ]
        ),
        "delete" => Dict(
            "tags" => ["Protected API"],
            "summary" => "Delete item (protected)",
            "security" => [Dict("bearerAuth" => [])],
            "parameters" => [
                Dict("name" => "id", "in" => "path", "required" => true, "schema" => Dict("type" => "string"))
            ]
        )
    ))
end

####################################
# MAIN                             #
####################################

function main()
    if !init_db_connection()
        println("Failed to start: Database connection error")
        exit(1)
    end

    println("DEMO_UNSAFE_ADMIN enabled: $DEMO_UNSAFE_ADMIN")
    println("JWT secret configured (non-default): ", JWT_SECRET != "change-me-in-production")
    println("Setting up API documentation...")

    setup_swagger_docs()

    println("Starting server on port $API_PORT...")
    serve(middleware=[JWTAuthMiddleware], port=API_PORT, host="0.0.0.0")
end

main()
