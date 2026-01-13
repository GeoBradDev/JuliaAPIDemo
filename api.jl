# api.jl
using Oxygen
using JSONWebTokens
using HTTP
using Dates
using LibPQ
using SHA
using JSON3

println("🚀 Starting JWT API Server...")

# Configuration from environment variables
const DB_HOST = get(ENV, "DB_HOST", "localhost")
const DB_PORT = get(ENV, "DB_PORT", "5432")
const DB_NAME = get(ENV, "DB_NAME", "jwt_api_db")
const DB_USER = get(ENV, "DB_USER", "api_user")
const DB_PASSWORD = get(ENV, "DB_PASSWORD", "password")
const JWT_SECRET = get(ENV, "JWT_SECRET", "change-me-in-production")
const API_PORT = parse(Int, get(ENV, "API_PORT", "8080"))

# Database connection string
const DB_CONN_STRING = "host=$DB_HOST port=$DB_PORT dbname=$DB_NAME user=$DB_USER password=$DB_PASSWORD"

# Global database connection
DB_CONN = nothing

function init_db_connection()
    """Initialize database connection with retry logic"""
    max_retries = 5
    retry_delay = 2

    for attempt in 1:max_retries
        try
            println("📊 Connecting to database (attempt $attempt/$max_retries)...")
            global DB_CONN = LibPQ.Connection(DB_CONN_STRING)
            println("✅ Database connected successfully!")
            return true
        catch e
            println("❌ Database connection failed: $e")
            if attempt < max_retries
                println("⏳ Retrying in $retry_delay seconds...")
                sleep(retry_delay)
            else
                println("💥 Failed to connect to database after $max_retries attempts")
                return false
            end
        end
    end
end

####################################
# DATABASE FUNCTIONS               #
####################################

function hash_token(token::String)
    """Create SHA-256 hash of token"""
    return bytes2hex(sha256(token))
end

function save_token_to_db(client_id::String, client_name::String, token::String,
                          expires_at::DateTime, created_by::String)
    """Save issued token to database"""
    token_hash = hash_token(token)

    query = """
        INSERT INTO api_tokens
        (client_id, client_name, token_hash, expires_at, created_by, active)
        VALUES (\$1, \$2, \$3, \$4, \$5, true)
        ON CONFLICT (client_id)
        DO UPDATE SET
            token_hash = EXCLUDED.token_hash,
            expires_at = EXCLUDED.expires_at,
            issued_at = NOW(),
            active = true
        RETURNING id
    """

    result = execute(DB_CONN, query, [
        client_id,
        client_name,
        token_hash,
        expires_at,
        created_by
    ])

    return result
end

function validate_token_in_db(token::String)
    """Validate token exists and is active in database"""
    token_hash = hash_token(token)

    query = """
        SELECT client_id, client_name, expires_at, active
        FROM api_tokens
        WHERE token_hash = \$1
    """

    result = execute(DB_CONN, query, [token_hash])

    if isempty(result)
        return nothing
    end

    row = result[1]

    if !row[:active]
        @warn "Token is revoked" client_id=row[:client_id]
        return nothing
    end

    if row[:expires_at] < now()
        @warn "Token is expired" client_id=row[:client_id]
        return nothing
    end

    # Update last_used_at
    update_query = """
        UPDATE api_tokens
        SET last_used_at = NOW()
        WHERE token_hash = \$1
    """
    execute(DB_CONN, update_query, [token_hash])

    return Dict(
        "client_id" => row[:client_id],
        "client_name" => row[:client_name]
    )
end

function revoke_token(client_id::String)
    """Revoke a token"""
    query = """
        UPDATE api_tokens
        SET active = false
        WHERE client_id = \$1
        RETURNING client_id, client_name
    """

    result = execute(DB_CONN, query, [client_id])
    return !isempty(result)
end

function log_token_usage(client_id::String, endpoint::String, method::String,
                        status_code::Int, ip_address::String="unknown")
    """Log API usage"""
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

function get_all_tokens()
    """Get all issued tokens"""
    query = """
        SELECT
            client_id,
            client_name,
            active,
            issued_at,
            expires_at,
            last_used_at,
            created_by
        FROM api_tokens
        ORDER BY issued_at DESC
    """

    result = execute(DB_CONN, query)

    return [
        Dict(
            "client_id" => row[:client_id],
            "client_name" => row[:client_name],
            "active" => row[:active],
            "issued_at" => string(row[:issued_at]),
            "expires_at" => string(row[:expires_at]),
            "last_used_at" => row[:last_used_at] === missing ? nothing : string(row[:last_used_at]),
            "created_by" => row[:created_by]
        )
        for row in result
    ]
end

####################################
# JWT FUNCTIONS                    #
####################################

function generate_api_jwt(client_id::String, client_name::String; expires_in_days::Int=365)
    """Generate JWT token"""
    now_unix = time()
    expires_unix = now_unix + (expires_in_days * 86400)

    claims = Dict(
        "sub" => client_id,
        "client_name" => client_name,
        "type" => "api_access",
        "iat" => now_unix,
        "exp" => expires_unix,
        "iss" => "jwt-api-server"
    )

    encoding = JSONWebTokens.HS256(JWT_SECRET)
    token = JSONWebTokens.encode(encoding, claims)

    # Convert Unix timestamp to DateTime
    expires_at = unix2datetime(expires_unix)

    return token, expires_at
end

function validate_api_jwt(token::String)
    """Validate JWT and check database"""
    try
        # Validate JWT signature
        encoding = JSONWebTokens.HS256(JWT_SECRET)
        claims = JSONWebTokens.decode(encoding, token)

        if claims["exp"] < time()
            return nothing
        end

        if get(claims, "type", "") != "api_access"
            return nothing
        end

        # Check database
        db_info = validate_token_in_db(token)
        if db_info === nothing
            return nothing
        end

        return merge(claims, db_info)

    catch e
        @error "JWT validation failed" exception=e
        return nothing
    end
end

####################################
# MIDDLEWARE                       #
####################################

function JWTAuthMiddleware(handler)
    return function(req::HTTP.Request)
        auth_header = get(req.headers, "Authorization", "")

        if !startswith(auth_header, "Bearer ")
            return HTTP.Response(401, JSON3.write(Dict(
                "error" => "Missing Bearer token"
            )))
        end

        token = replace(auth_header, "Bearer " => "", count=1)

        claims = validate_api_jwt(token)
        if claims === nothing
            return HTTP.Response(401, JSON3.write(Dict(
                "error" => "Invalid or expired token"
            )))
        end

        # Get client IP
        ip_address = get(req.headers, "X-Forwarded-For",
                        get(req.headers, "X-Real-IP", "unknown"))

        # Log usage (async)
        @async log_token_usage(
            claims["client_id"],
            req.target,
            req.method,
            200,
            ip_address
        )

        req.context = Dict(
            "client_id" => claims["client_id"],
            "client_name" => claims["client_name"]
        )

        return handler(req)
    end
end

####################################
# ROUTES                           #
####################################

# Health check
@get "/health" function()
    db_status = try
        execute(DB_CONN, "SELECT 1")
        "connected"
    catch
        "disconnected"
    end

    return Dict(
        "status" => "ok",
        "timestamp" => now(),
        "database" => db_status
    )
end

# Issue new token (admin endpoint)
@post "/admin/issue-token" function(req::HTTP.Request)
    body = JSON3.read(req.body)

    client_id = get(body, :client_id, "")
    client_name = get(body, :client_name, "")
    expires_in_days = get(body, :expires_in_days, 365)
    created_by = get(body, :created_by, "admin")

    if isempty(client_id) || isempty(client_name)
        return HTTP.Response(400, JSON3.write(Dict(
            "error" => "client_id and client_name required"
        )))
    end

    try
        token, expires_at = generate_api_jwt(client_id, client_name,
                                            expires_in_days=expires_in_days)

        save_token_to_db(client_id, client_name, token, expires_at, created_by)

        return Dict(
            "success" => true,
            "client_id" => client_id,
            "client_name" => client_name,
            "token" => token,
            "token_type" => "Bearer",
            "expires_in_days" => expires_in_days,
            "expires_at" => string(expires_at),
            "usage" => "Authorization: Bearer <token>"
        )

    catch e
        @error "Failed to issue token" exception=e
        return HTTP.Response(500, JSON3.write(Dict(
            "error" => "Failed to issue token"
        )))
    end
end

# List all tokens
@get "/admin/tokens" function()
    try
        tokens = get_all_tokens()
        return Dict("tokens" => tokens)
    catch e
        @error "Failed to fetch tokens" exception=e
        return HTTP.Response(500, JSON3.write(Dict(
            "error" => "Failed to fetch tokens"
        )))
    end
end

# Revoke token
@delete "/admin/tokens/:client_id" function(req::HTTP.Request, client_id::String)
    try
        revoked = revoke_token(client_id)

        if revoked
            return Dict(
                "success" => true,
                "message" => "Token revoked",
                "client_id" => client_id
            )
        else
            return HTTP.Response(404, JSON3.write(Dict(
                "error" => "Token not found"
            )))
        end
    catch e
        return HTTP.Response(500, JSON3.write(Dict(
            "error" => "Failed to revoke token"
        )))
    end
end

# Get usage stats
@get "/admin/usage/:client_id" function(req::HTTP.Request, client_id::String)
    query = """
        SELECT
            DATE(timestamp) as date,
            COUNT(*) as request_count,
            COUNT(DISTINCT endpoint) as unique_endpoints
        FROM token_usage_log
        WHERE client_id = \$1
        AND timestamp > NOW() - INTERVAL '30 days'
        GROUP BY DATE(timestamp)
        ORDER BY date DESC
    """

    result = execute(DB_CONN, query, [client_id])

    usage = [
        Dict(
            "date" => string(row[:date]),
            "request_count" => row[:request_count],
            "unique_endpoints" => row[:unique_endpoints]
        )
        for row in result
    ]

    return Dict("client_id" => client_id, "usage" => usage)
end

# Protected endpoints
@get "/api/data" function(req::HTTP.Request)
    return Dict(
        "data" => [
            Dict("id" => 1, "value" => "Item 1"),
            Dict("id" => 2, "value" => "Item 2")
        ],
        "requested_by" => req.context["client_name"]
    )
end

@post "/api/data" function(req::HTTP.Request)
    body = JSON3.read(req.body)

    return Dict(
        "message" => "Data created",
        "id" => rand(1:1000),
        "data" => body,
        "created_by" => req.context["client_name"]
    )
end

####################################
# MAIN                             #
####################################

function main()
    # Initialize database connection
    if !init_db_connection()
        println("💥 Failed to start: Database connection error")
        exit(1)
    end

    println("🔐 JWT Secret: $(JWT_SECRET[1:10])... (first 10 chars)")
    println("🌐 Starting server on port $API_PORT...")

    # Start server with middleware
    serve(middleware=[JWTAuthMiddleware], port=API_PORT, host="0.0.0.0")
end

# Run the server
main()