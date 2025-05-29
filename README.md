# Shuttle MCP Server Template

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server template built with Rust, Axum, and Shuttle. This template provides OAuth 2.1 authentication via Auth0, a PostgreSQL database, AI tool integration with OpenAI, and a complete MCP JSON-RPC 2.0 implementation.

## Features

- 🔐 **OAuth 2.1 Authentication** - Secure user authentication via Auth0 with Google login
- 🗄️ **PostgreSQL Database** - Managed database with automatic migrations via Shuttle
- 🤖 **AI Tool Integration** - OpenAI-powered completion and summarization tools via the `rig` crate
- 📊 **Database Tools** - Built-in user statistics and data management tools
- 🔧 **Text Processing Tools** - Length calculation, transformation, and search utilities
- ⚡ **JSON-RPC 2.0** - Complete MCP protocol implementation with dynamic tool registry
- 🚀 **Shuttle Deployment** - One-command deployment to the cloud
- 🛡️ **Secure Sessions** - JWT-based session management with HttpOnly cookies

## Quick Start

### Prerequisites

1. Install [Rust](https://rustup.rs/)
2. Install [Shuttle CLI](https://docs.shuttle.rs/getting-started/installation):
   ```bash
   cargo install cargo-shuttle
   ```
3. Create a [Shuttle account](https://shuttle.rs/)
4. Create an [Auth0 account](https://auth0.com/)

### Local Development

1. **Clone this template:**
   ```bash
   git clone <your-repo-url>
   cd mcp-server
   ```

2. **Set up Auth0:**
   - Create a new Application (Regular Web App) in your Auth0 dashboard
   - Enable Google social connection (or other providers)
   - Note your Auth0 domain, client ID, and client secret

3. **Create local secrets file:**
   ```bash
   # Create Secrets.toml in the project root
   touch Secrets.toml
   ```

4. **Configure secrets:**
   ```toml
   # Secrets.toml
   AUTH0_DOMAIN = 'your-tenant.auth0.com'
   AUTH0_CLIENT_ID = 'your-client-id'
   AUTH0_CLIENT_SECRET = 'your-client-secret'
   AUTH0_CALLBACK_URL = 'http://localhost:8000/auth/callback'
   SESSION_JWT_SECRET = 'your-very-long-random-secret-key-at-least-32-chars'
   OPENAI_API_KEY = 'sk-your-openai-api-key'  # Optional: for AI tools
   ```

5. **Run locally:**
   ```bash
   cargo shuttle run
   ```

6. **Test the server:**
   - Visit `http://localhost:8000/auth/login` to test authentication
   - Test MCP endpoint: `POST http://localhost:8000/mcp` with JSON-RPC requests
   - Example MCP request:
     ```json
     {
       "jsonrpc": "2.0",
       "method": "list_tools",
       "id": 1
     }
     ```

### Cloud Deployment

1. **Login to Shuttle:**
   ```bash
   cargo shuttle login
   ```

2. **Create a new project:**
   ```bash
   cargo shuttle project new --name your-mcp-server
   ```

3. **Update Auth0 settings:**
   - In your Auth0 application settings:
   - Set Allowed Callback URLs to: `https://your-mcp-server.shuttleapp.rs/auth/callback`
   - Set Allowed Logout URLs to: `https://your-mcp-server.shuttleapp.rs/`

4. **Deploy:**
   ```bash
   cargo shuttle deploy
   ```

5. **Set production secrets:**
   ```bash
   # Update your Secrets.toml with production URLs
   AUTH0_CALLBACK_URL = 'https://your-mcp-server.shuttleapp.rs/auth/callback'
   # Keep other secrets the same
   ```

6. **Redeploy with updated secrets:**
   ```bash
   cargo shuttle deploy
   ```

## Available Endpoints

### Authentication
- `GET /auth/login` - Initiate OAuth login flow
- `GET /auth/callback` - OAuth callback handler
- `GET /auth/me` - Get current user info (requires authentication)
- `GET /auth/logout` - Logout and clear session
- `GET /welcome` - Welcome page after successful login

### MCP Protocol
- `POST /mcp` - Main MCP JSON-RPC 2.0 endpoint (`initialize` and notifications are public, all other methods require authentication)

## Available MCP Tools

All tools follow the official MCP JSON-RPC 2.0 specification and support proper initialization:

### Core MCP Methods
- `initialize` - Initialize the MCP connection and exchange capabilities
- `notifications/initialized` - Acknowledge successful initialization

### Tool Management
- `tools/list` - List all available tools with full JSON schemas
- `tools/call` - Execute tools using the standard MCP format with proper response structure

### Resource Management
- `resources/list` - List available data resources
- `resources/read` - Read resource content by URI

### Prompt Management
- `prompts/list` - List available prompt templates
- `prompts/get` - Get specific prompt with arguments

### Available Tools (via `tools/call`)
- `text_length` - Get character count of text
- `text_transform` - Transform text (uppercase, lowercase, titlecase)
- `text_search` - Search for patterns in text
- `timestamp` - Get current UTC timestamp
- `ai_complete` - Complete text prompts using GPT (requires OpenAI API key)
- `ai_summarize` - Summarize long text content (requires OpenAI API key)
- `user_stats` - Get user statistics from the database

### Available Resources (via `resources/read`)
- `user://stats` - Current user statistics in JSON format

### Available Prompts (via `prompts/get`)
- `code_review` - Generate code review prompts (arguments: `code`, `language`)
- `explain_error` - Generate error explanation prompts (arguments: `error`)

## MCP Protocol Implementation

This server implements the complete MCP JSON-RPC 2.0 specification with **mandatory authentication** for most operations:

### Authentication Requirements (Per MCP Specification)

- **Public Methods (No Authentication Required):**
  - `initialize` - Used for initial MCP handshake and capability exchange
  - `notifications/initialized` - Acknowledges successful initialization
  - `exit` - Client exit notification

- **Protected Methods (Authentication Required):**
  - `tools/list` - List all available tools
  - `tools/call` - Execute any tool
  - `resources/list` - List available data resources  
  - `resources/read` - Read resource content
  - `prompts/list` - List available prompt templates
  - `prompts/get` - Get specific prompts

**Authentication Process:**
1. Users must first authenticate via the OAuth 2.1 flow at `/auth/login`
2. Successful authentication creates a secure session JWT cookie
3. All protected MCP method calls must include this session cookie
4. Unauthenticated requests to protected methods return JSON-RPC error code -32001

This authentication requirement ensures that only authorized users can access your tools, data resources, and prompts while maintaining the standard MCP initialization flow for client compatibility.

### Initialization Flow
1. Client sends `initialize` request with protocol version and capabilities (no auth required)
2. Server responds with server info and supported capabilities
3. Client sends `notifications/initialized` to complete handshake (no auth required)
4. Client must authenticate user via OAuth flow before calling any protected methods
5. All subsequent tool/resource/prompt operations require valid session authentication

### Example MCP Requests

**Initialize the connection (public):**
```json
{
  "jsonrpc": "2.0",
  "method": "initialize", 
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "test-client", "version": "1.0.0"}
  },
  "id": 0
}
```

**List available tools (requires authentication):**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 1
}
```

**Call a tool (requires authentication):**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "text_length",
    "arguments": {"text": "Hello world"}
  },
  "id": 2
}
```

**Read a resource (requires authentication):**
```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {"uri": "user://stats"},
  "id": 3
}
```

**Note:** All requests except `initialize` and notifications must include a valid session cookie obtained through the OAuth 2.1 authentication flow.

## How the OAuth 2.1 Flow Works

- This server is deployed on Shuttle and exposes MCP tools and endpoints.
- When an MCP client (e.g., Cursor, Claude, custom LLM agent) connects and needs to authenticate a user, it will redirect the user to `/auth/login`.
- The user logs in with Google (or other provider) via Auth0.
- On success, Auth0 redirects back to `/auth/callback`, which issues a session JWT and sets it as a secure cookie.
- The user is redirected to `/welcome` (or the MCP client can handle the redirect and extract the session cookie).
- All subsequent requests from the MCP client include the session cookie for authentication.
- The `/auth/me` endpoint can be used by the MCP client to verify the user's identity and retrieve user info.
- `/auth/logout` clears the session and logs the user out.

This flow ensures that only authenticated users (via Google/Auth0) can access protected MCP tools and endpoints, and that the MCP client can securely manage user sessions.

## Adding New Functionality

### Adding New MCP Tools

1. **Create your tool function** in `src/tools/` (create new modules as needed):
   ```rust
   // src/tools/my_module.rs
   pub fn my_new_tool(input: &str) -> String {
       // Your tool logic here
       format!("Processed: {}", input)
   }
   ```

2. **Register the tool** in `src/tools.rs`:
   ```rust
   pub static TOOL_REGISTRY: Lazy<Vec<Tool>> = Lazy::new(|| {
       vec![
           // ... existing tools ...
           Tool {
               name: "my_new_tool",
               description: "Description of what this tool does.",
           },
       ]
   });
   ```

3. **Add the handler** in `src/mcp.rs`:
   ```rust
   match req.method.as_str() {
       // ... existing cases ...
       "my_new_tool" => {
           if let Some(params) = req.params {
               if let Some(input) = params.get("input").and_then(|v| v.as_str()) {
                   let result = crate::tools::my_module::my_new_tool(input);
                   response.result = Some(serde_json::json!({"result": result}));
               } else {
                   response.error = Some(serde_json::json!({
                       "code": -32602, 
                       "message": "Missing 'input' param"
                   }));
               }
           }
       }
   }
   ```

### Adding New Database Models

1. **Create migration** in `migrations/`:
   ```sql
   -- migrations/0002_create_your_table.sql
   CREATE TABLE IF NOT EXISTS your_table (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       name TEXT NOT NULL,
       created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
   );
   ```

2. **Add model** in `src/auth/models.rs` or create new model files:
   ```rust
   #[derive(Debug, Serialize, Deserialize)]
   pub struct YourModel {
       pub id: uuid::Uuid,
       pub name: String,
       pub created_at: chrono::DateTime<chrono::Utc>,
   }
   ```

### Adding New Authentication Routes

Add new routes in `src/main.rs`:
```rust
let router = Router::new()
    // ... existing routes ...
    .route("/your-route", get(your_handler))
    .with_state((pool, secrets));
```

Create handlers in `src/auth/handlers.rs` that accept `AuthenticatedUser` for protected routes.

## Project Structure

```
src/
├── main.rs              # Application entry point and routing
├── auth/
│   ├── mod.rs           # Auth module exports
│   ├── handlers.rs      # OAuth and session handlers
│   ├── middleware.rs    # Authentication middleware
│   └── models.rs        # User and auth data models
├── database.rs          # Database initialization and migrations
├── mcp.rs              # MCP JSON-RPC protocol implementation
└── tools/              # MCP tool implementations
    ├── mod.rs          # Tool registry and exports
    ├── ai.rs           # OpenAI integration tools
    ├── db.rs           # Database query tools
    ├── text.rs         # Text processing utilities
    └── utils.rs        # General utility tools
migrations/             # Database migration files
```

## Environment Variables

Required in `Secrets.toml`:

```toml
# Auth0 Configuration
AUTH0_DOMAIN = 'your-tenant.auth0.com'
AUTH0_CLIENT_ID = 'your-auth0-client-id'
AUTH0_CLIENT_SECRET = 'your-auth0-client-secret'
AUTH0_CALLBACK_URL = 'https://your-app.shuttleapp.rs/auth/callback'

# Session Management
SESSION_JWT_SECRET = 'your-32-char-minimum-secret-key'

# Optional: AI Tools
OPENAI_API_KEY = 'sk-your-openai-api-key'
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally with `cargo shuttle run`
5. Deploy and test in production
6. Submit a pull request

## License

This template is provided under the MIT License. See LICENSE for details.

## Resources

- [Shuttle Documentation](https://docs.shuttle.rs/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Auth0 Documentation](https://auth0.com/docs)
- [Axum Web Framework](https://docs.rs/axum/)
- [OpenAI API](https://platform.openai.com/docs)
