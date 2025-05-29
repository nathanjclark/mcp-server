# Shuttle MCP Server

A complete [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server built with Rust, Axum, and Shuttle. This template provides everything you need to build a production-ready MCP server with OAuth 2.1 authentication, database integration, AI tools, and a clean registry-based architecture.

## 🚀 What You Get

- **🔐 OAuth 2.1 Authentication** - Secure user authentication via Auth0 with Google login
- **🗄️ PostgreSQL Database** - Managed database with automatic migrations  
- **🤖 AI Integration** - OpenAI-powered tools via the `rig` crate
- **📊 Built-in Tools** - Text processing, database queries, timestamps, and more
- **🔧 Registry System** - Centralized management of tools, resources, and prompts
- **⚡ Full MCP Compliance** - Complete JSON-RPC 2.0 implementation with proper authentication
- **🚀 One-Click Deploy** - Deploy to Shuttle with a single command
- **🛡️ Production Ready** - JWT sessions, security best practices, comprehensive error handling

## 🏗️ Architecture Overview

This server implements the complete MCP specification with authentication:

```
┌─────────────────┐    JSON-RPC 2.0     ┌─────────────────┐
│   MCP Client    │ ────────────────────▶│  Shuttle MCP    │
│ (Claude, etc.)  │                      │     Server      │
│                 │ ◄──── Tools ─────────│                 │
│                 │ ◄── Resources ───────│  🔐 OAuth 2.1   │
│                 │ ◄─── Prompts ────────│  🗄️ PostgreSQL  │
└─────────────────┘                      │  🤖 AI Tools    │
                                         └─────────────────┘
```

### Authentication Flow

- **Public Methods**: `initialize`, `notifications/initialized`, `exit` 
- **Protected Methods**: All tools, resources, and prompts require authentication
- **Security**: Users authenticate via OAuth 2.1 before accessing any functionality

## 📋 Prerequisites

1. **Rust** - [Install from rustup.rs](https://rustup.rs/)
2. **Shuttle CLI** - Recommended installation method:
   ```bash
   # Linux/macOS
   curl -sSfL https://www.shuttle.dev/install | bash
   
   # Windows (PowerShell)
   # iwr https://www.shuttle.dev/install-win | iex
   
   # Alternative: Using Cargo
   # cargo install cargo-shuttle
   ```
3. **Auth0 Account** - [Free at auth0.com](https://auth0.com/)

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <your-repo-url>
cd mcp-server
```

### 2. Configure Auth0

1. Create a new **Application** (Regular Web App) in Auth0
2. Enable **Google Social Connection** 
3. Note your domain, client ID, and client secret

### 3. Create Secrets

```bash
# Create Secrets.toml in project root
cat > Secrets.toml << EOF
AUTH0_DOMAIN = 'your-tenant.auth0.com'
AUTH0_CLIENT_ID = 'your-client-id'
AUTH0_CLIENT_SECRET = 'your-client-secret'
AUTH0_CALLBACK_URL = 'http://localhost:8000/auth/callback'
SESSION_JWT_SECRET = 'your-very-long-random-secret-key-at-least-32-chars'
OPENAI_API_KEY = 'sk-your-openai-api-key'  # Optional
EOF
```

### 4. Run Locally

```bash
shuttle run
```

### 5. Test Your Server

```bash
# Test authentication
curl http://localhost:8000/auth/login

# Test MCP endpoint (initialize is public)
curl -X POST http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": {"name": "test-client", "version": "1.0.0"}
    },
    "id": 1
  }'
```

## 🌐 Deploy to Production

### 1. Setup Shuttle

```bash
shuttle login
```

### 2. Update Auth0 Settings

In your Auth0 application:
- **Allowed Callback URLs**: `https://your-mcp-server.shuttleapp.rs/auth/callback`
- **Allowed Logout URLs**: `https://your-mcp-server.shuttleapp.rs/`

### 3. Update Production Secrets

```toml
# Update Secrets.toml
AUTH0_CALLBACK_URL = 'https://your-mcp-server.shuttleapp.rs/auth/callback'
# Keep other secrets the same
```

### 4. Deploy

```bash
shuttle deploy
```

## 🔌 API Endpoints

### Authentication
- `GET /auth/login` - Start OAuth flow
- `GET /auth/callback` - OAuth callback 
- `GET /auth/me` - Get current user (authenticated)
- `GET /auth/logout` - Logout and clear session
- `GET /welcome` - Welcome page after login

### MCP Protocol
- `POST /mcp` - Main MCP JSON-RPC 2.0 endpoint

## 🛠️ Available MCP Capabilities

### Core Protocol Methods

| Method | Authentication | Description |
|--------|---------------|-------------|
| `initialize` | ❌ Public | Exchange capabilities and server info |
| `notifications/initialized` | ❌ Public | Complete MCP handshake |
| `tools/list` | ✅ Required | List available tools with schemas |
| `tools/call` | ✅ Required | Execute tools |
| `resources/list` | ✅ Required | List available data resources |
| `resources/read` | ✅ Required | Read resource content |
| `prompts/list` | ✅ Required | List available prompt templates |
| `prompts/get` | ✅ Required | Get specific prompts |

### Built-in Tools

| Tool | Description | Arguments |
|------|-------------|-----------|
| `text_length` | Get character count | `text: string` |
| `text_transform` | Transform text case | `text: string, transform: enum` |
| `text_search` | Search for patterns | `text: string, pattern: string` |
| `timestamp` | Get current UTC time | None |
| `ai_complete` | Complete text prompts | `prompt: string` |
| `ai_summarize` | Summarize long text | `text: string` |
| `user_stats` | Get database statistics | None |

### Built-in Resources

| Resource | Description | Content Type |
|----------|-------------|--------------|
| `user://stats` | User statistics from database | `application/json` |

### Built-in Prompts

| Prompt | Description | Arguments |
|--------|-------------|-----------|
| `code_review` | Generate code review prompts | `code: string, language?: string` |
| `explain_error` | Generate error explanation prompts | `error: string` |

## 🔧 Extending Your Server

### Adding New Tools

1. **Implement the tool** in `src/tools/`:

```rust
// src/tools/my_tools.rs
pub fn calculate_fibonacci(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => calculate_fibonacci(n - 1) + calculate_fibonacci(n - 2)
    }
}
```

2. **Register in the registry** (`src/registries.rs`):

```rust
Tool {
    name: "fibonacci",
    description: "Calculate Fibonacci number",
},
```

3. **Add the handler** in `src/mcp.rs` (`handle_tool_call` function):

```rust
"fibonacci" => {
    let n = arguments.get("n").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let result = crate::tools::my_tools::calculate_fibonacci(n);
    Ok(serde_json::json!({
        "content": [{
            "type": "text",
            "text": format!("Fibonacci({}) = {}", n, result)
        }]
    }))
}
```

4. **Add the schema** in `get_tool_schema` function:

```rust
"fibonacci" => serde_json::json!({
    "type": "object",
    "properties": {
        "n": {
            "type": "integer",
            "description": "The position in Fibonacci sequence",
            "minimum": 0
        }
    },
    "required": ["n"]
}),
```

### Adding New Resources

1. **Register the resource** (`src/registries.rs`):

```rust
Resource {
    uri: "system://health",
    name: "System Health",
    description: "Current system health metrics",
    mime_type: "application/json",
},
```

2. **Add the handler** in `handle_resource_read` function (`src/mcp.rs`):

```rust
"system://health" => {
    let health_data = serde_json::json!({
        "status": "healthy",
        "uptime": "2h 30m",
        "memory_usage": "45%"
    });
    Ok(serde_json::json!({
        "contents": [{
            "uri": uri,
            "mimeType": resource.mime_type,
            "text": serde_json::to_string_pretty(&health_data).unwrap()
        }]
    }))
}
```

### Adding New Prompts

1. **Register the prompt** (`src/registries.rs`):

```rust
Prompt {
    name: "write_tests",
    description: "Generate unit tests for code",
    arguments: vec![
        PromptArgument {
            name: "code",
            description: "The code to test",
            required: true,
        },
        PromptArgument {
            name: "framework",
            description: "Testing framework",
            required: false,
        },
    ],
},
```

2. **Add the handler** in `handle_prompt_get` function (`src/mcp.rs`):

```rust
"write_tests" => {
    let code = arguments.and_then(|args| args.get("code"))
        .and_then(|v| v.as_str()).unwrap_or("// No code provided");
    let framework = arguments.and_then(|args| args.get("framework"))
        .and_then(|v| v.as_str()).unwrap_or("jest");

    Ok(serde_json::json!({
        "messages": [{
            "role": "user",
            "content": {
                "type": "text",
                "text": format!("Write {} unit tests for this code:\n\n{}", framework, code)
            }
        }]
    }))
}
```

## 📁 Project Structure

```
src/
├── main.rs              # Application entry point and routing
├── auth/                # Authentication system
│   ├── mod.rs           # Module exports
│   ├── handlers.rs      # OAuth and session handlers
│   ├── middleware.rs    # Authentication middleware and helpers
│   └── models.rs        # User and auth data models
├── database.rs          # Database initialization and migrations
├── mcp.rs              # MCP JSON-RPC protocol implementation
├── registries.rs        # Central registries for tools, resources, and prompts
└── tools/              # Tool implementations
    ├── mod.rs          # Tool module exports
    ├── ai.rs           # OpenAI integration tools
    ├── db.rs           # Database query tools
    ├── text.rs         # Text processing utilities
    └── utils.rs        # General utility tools
migrations/             # Database migration files
```

## 🔐 Security Features

- **OAuth 2.1 Flow**: Industry-standard authentication
- **JWT Sessions**: Secure, stateless session management
- **Method Protection**: All tools/resources require authentication
- **HTTPS Ready**: Built for secure production deployment
- **Input Validation**: Comprehensive parameter validation
- **Error Handling**: Safe error responses without information leakage

## 🧪 Example MCP Requests

### Initialize Connection (Public)
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "test-client", "version": "1.0.0"}
  },
  "id": 1
}
```

### List Tools (Requires Auth)
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "id": 2
}
```

### Call a Tool (Requires Auth)
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "text_length",
    "arguments": {"text": "Hello, world!"}
  },
  "id": 3
}
```

### Read a Resource (Requires Auth)
```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {"uri": "user://stats"},
  "id": 4
}
```

## 🌟 Why This Template?

### ✅ MCP Compliant
- Full JSON-RPC 2.0 support
- Complete capability negotiation
- Proper authentication flow
- Standard error codes

### ✅ Cloud Native
- One-command deployment to Shuttle
- Managed PostgreSQL database
- Environment-based configuration
- Production monitoring ready

## 🔧 Environment Variables

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

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and test locally
4. Commit your changes: `git commit -m 'Add amazing feature'`
5. Push to the branch: `git push origin feature/amazing-feature`
6. Open a Pull Request

## 📚 Learn More

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [Shuttle Documentation](https://docs.shuttle.rs/)
- [Auth0 Documentation](https://auth0.com/docs)
- [Axum Web Framework](https://docs.rs/axum/)
- [OpenAI API Documentation](https://platform.openai.com/docs)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

