use crate::auth::middleware::extract_authenticated_user_for_mcp;
use crate::registries::{PROMPT_REGISTRY, RESOURCE_REGISTRY, TOOL_REGISTRY};
use axum::{
    extract::{Json, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{error, info};

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Value>, // Optional for notifications
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct ServerCapabilities {
    pub tools: Option<ToolsCapability>,
    pub resources: Option<ResourcesCapability>,
    pub prompts: Option<PromptsCapability>,
}

#[derive(Debug, Serialize)]
pub struct ToolsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Serialize)]
pub struct ResourcesCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
    pub subscribe: bool,
}

#[derive(Debug, Serialize)]
pub struct PromptsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Serialize)]
pub struct InitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ServerInfo,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Serialize)]
pub struct Resource {
    pub uri: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Prompt {
    pub name: String,
    pub description: Option<String>,
    pub arguments: Option<Vec<PromptArgument>>,
}

#[derive(Debug, Serialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: Option<String>,
    pub required: Option<bool>,
}

/// Check if a method requires authentication
fn requires_authentication(method: &str) -> bool {
    !matches!(method, "initialize" | "notifications/initialized" | "exit")
}

pub async fn mcp_handler(
    headers: HeaderMap,
    State((pool, secrets)): State<(sqlx::PgPool, shuttle_runtime::SecretStore)>,
    Json(req): Json<JsonRpcRequest>,
) -> Response {
    info!("MCP request: method={}, id={:?}", req.method, req.id);

    // Handle notifications (no response required)
    if req.id.is_none() {
        return handle_notification(req).await;
    }

    // Check if authentication is required for this method
    let _authenticated_user = if requires_authentication(&req.method) {
        match extract_authenticated_user_for_mcp(&headers, &secrets).await {
            Ok(user) => {
                info!("Authenticated request from user: {}", user.email);
                Some(user)
            }
            Err(error_json) => {
                error!("Authentication failed for method: {}", req.method);

                // Return proper OAuth 2.1 error response with WWW-Authenticate header
                let mut response = axum::Json(JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(error_json),
                    id: req.id,
                })
                .into_response();

                // Add WWW-Authenticate header as required by MCP spec
                let www_auth_value = HeaderValue::from_static(
                    r#"Bearer realm="mcp-server", error="invalid_token", error_description="Authentication required""#,
                );
                response
                    .headers_mut()
                    .insert("WWW-Authenticate", www_auth_value);

                // Set status to 401 Unauthorized
                *response.status_mut() = StatusCode::UNAUTHORIZED;

                return response;
            }
        }
    } else {
        None
    };

    let mut response = JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: None,
        error: None,
        id: req.id.clone(),
    };

    match req.method.as_str() {
        "initialize" => {
            info!("Handling initialize request (public)");
            let init_result = InitializeResult {
                protocol_version: "2024-11-05".to_string(),
                capabilities: ServerCapabilities {
                    tools: Some(ToolsCapability {
                        list_changed: false,
                    }),
                    resources: Some(ResourcesCapability {
                        list_changed: false,
                        subscribe: false,
                    }),
                    prompts: Some(PromptsCapability {
                        list_changed: false,
                    }),
                },
                server_info: ServerInfo {
                    name: "Shuttle MCP Server".to_string(),
                    version: "1.0.0".to_string(),
                },
            };
            response.result = Some(serde_json::to_value(init_result).unwrap());
        }
        "tools/list" => {
            info!("Handling tools/list request (authenticated)");
            let tools: Vec<Tool> = TOOL_REGISTRY
                .iter()
                .map(|tool| Tool {
                    name: tool.name.to_string(),
                    description: tool.description.to_string(),
                    input_schema: get_tool_schema(tool.name),
                })
                .collect();

            response.result = Some(serde_json::json!({
                "tools": tools
            }));
        }
        "tools/call" => {
            info!("Handling tools/call request (authenticated)");
            match handle_tool_call(req.params, &pool, &secrets).await {
                Ok(result) => response.result = Some(result),
                Err(error) => response.error = Some(error),
            }
        }
        "resources/list" => {
            info!("Handling resources/list request (authenticated)");
            let resources: Vec<Resource> = RESOURCE_REGISTRY
                .iter()
                .map(|resource| Resource {
                    uri: resource.uri.to_string(),
                    name: resource.name.to_string(),
                    description: Some(resource.description.to_string()),
                    mime_type: Some(resource.mime_type.to_string()),
                })
                .collect();
            response.result = Some(serde_json::json!({
                "resources": resources
            }));
        }
        "resources/read" => {
            info!("Handling resources/read request (authenticated)");
            if let Some(params) = req.params {
                if let Some(uri) = params.get("uri").and_then(|v| v.as_str()) {
                    match handle_resource_read(uri, &pool).await {
                        Ok(result) => response.result = Some(result),
                        Err(error) => response.error = Some(error),
                    }
                } else {
                    response.error = Some(serde_json::json!({
                        "code": -32602,
                        "message": "Invalid params: missing 'uri'"
                    }));
                }
            } else {
                response.error = Some(serde_json::json!({
                    "code": -32602,
                    "message": "Missing params"
                }));
            }
        }
        "prompts/list" => {
            info!("Handling prompts/list request (authenticated)");
            let prompts: Vec<Prompt> = PROMPT_REGISTRY
                .iter()
                .map(|prompt| Prompt {
                    name: prompt.name.to_string(),
                    description: Some(prompt.description.to_string()),
                    arguments: Some(
                        prompt
                            .arguments
                            .iter()
                            .map(|arg| PromptArgument {
                                name: arg.name.to_string(),
                                description: Some(arg.description.to_string()),
                                required: Some(arg.required),
                            })
                            .collect(),
                    ),
                })
                .collect();
            response.result = Some(serde_json::json!({
                "prompts": prompts
            }));
        }
        "prompts/get" => {
            info!("Handling prompts/get request (authenticated)");
            if let Some(params) = req.params {
                if let Some(name) = params.get("name").and_then(|v| v.as_str()) {
                    match handle_prompt_get(name, params.get("arguments")).await {
                        Ok(result) => response.result = Some(result),
                        Err(error) => response.error = Some(error),
                    }
                } else {
                    response.error = Some(serde_json::json!({
                        "code": -32602,
                        "message": "Invalid params: missing 'name'"
                    }));
                }
            } else {
                response.error = Some(serde_json::json!({
                    "code": -32602,
                    "message": "Missing params"
                }));
            }
        }
        _ => {
            error!("Unknown method: {}", req.method);
            response.error = Some(serde_json::json!({
                "code": -32601,
                "message": "Method not found"
            }));
        }
    }

    (StatusCode::OK, axum::Json(response)).into_response()
}

async fn handle_notification(req: JsonRpcRequest) -> Response {
    info!("Handling notification: {}", req.method);

    match req.method.as_str() {
        "notifications/initialized" => {
            info!("Client initialized successfully");
        }
        "exit" => {
            info!("Client exiting");
        }
        _ => {
            info!("Unknown notification: {}", req.method);
        }
    }

    // Notifications don't send responses
    StatusCode::NO_CONTENT.into_response()
}

async fn handle_tool_call(
    params: Option<Value>,
    pool: &sqlx::PgPool,
    secrets: &shuttle_runtime::SecretStore,
) -> Result<Value, Value> {
    let params = params.ok_or_else(|| {
        serde_json::json!({
            "code": -32602,
            "message": "Missing params"
        })
    })?;

    let tool_name = params.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
        serde_json::json!({
            "code": -32602,
            "message": "Missing 'name' parameter"
        })
    })?;

    // Fix the temporary value issue by creating a binding
    let empty_args = serde_json::json!({});
    let arguments = params.get("arguments").unwrap_or(&empty_args);

    match tool_name {
        "text_length" => {
            let text = arguments
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'text' argument"
                    })
                })?;
            let len = crate::tools::text::text_length(text);
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!("The text has {} characters", len)
                }]
            }))
        }
        "text_transform" => {
            let text = arguments
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'text' argument"
                    })
                })?;
            let transform = arguments
                .get("transform")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'transform' argument"
                    })
                })?;

            if let Some(result) = crate::tools::text::text_transform(text, transform) {
                Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": result
                    }]
                }))
            } else {
                Err(serde_json::json!({
                    "code": -32602,
                    "message": "Invalid transform type"
                }))
            }
        }
        "text_search" => {
            let text = arguments
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'text' argument"
                    })
                })?;
            let pattern = arguments
                .get("pattern")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'pattern' argument"
                    })
                })?;

            let found = crate::tools::text::text_search(text, pattern);
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": if found { "Pattern found" } else { "Pattern not found" }
                }]
            }))
        }
        "timestamp" => {
            let ts = crate::tools::utils::timestamp();
            Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!("Current timestamp: {}", ts)
                }]
            }))
        }
        "ai_complete" => {
            let prompt = arguments
                .get("prompt")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'prompt' argument"
                    })
                })?;

            match crate::tools::ai::ai_complete(prompt, secrets).await {
                Some(completion) => Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": completion
                    }]
                })),
                None => Err(serde_json::json!({
                    "code": -32001,
                    "message": "AI completion failed or not configured"
                })),
            }
        }
        "ai_summarize" => {
            let text = arguments
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    serde_json::json!({
                        "code": -32602,
                        "message": "Missing 'text' argument"
                    })
                })?;

            match crate::tools::ai::ai_summarize(text, secrets).await {
                Some(summary) => Ok(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": summary
                    }]
                })),
                None => Err(serde_json::json!({
                    "code": -32001,
                    "message": "AI summarize failed or not configured"
                })),
            }
        }
        "user_stats" => match crate::tools::db::user_stats(pool).await {
            Ok(stats) => Ok(serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!("User stats: {}", serde_json::to_string_pretty(&stats).unwrap())
                }]
            })),
            Err(e) => {
                error!("Failed to get user stats: {}", e);
                Err(serde_json::json!({
                    "code": -32002,
                    "message": "Failed to get user stats"
                }))
            }
        },
        _ => Err(serde_json::json!({
            "code": -32601,
            "message": "Tool not found"
        })),
    }
}

async fn handle_resource_read(uri: &str, pool: &sqlx::PgPool) -> Result<Value, Value> {
    // First check if the resource URI exists in our registry
    let resource = RESOURCE_REGISTRY
        .iter()
        .find(|r| r.uri == uri)
        .ok_or_else(|| {
            serde_json::json!({
                "code": -32001,
                "message": "Resource not found"
            })
        })?;

    match uri {
        "user://stats" => match crate::tools::db::user_stats(pool).await {
            Ok(stats) => Ok(serde_json::json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": resource.mime_type,
                    "text": serde_json::to_string_pretty(&stats).unwrap()
                }]
            })),
            Err(e) => {
                error!("Failed to read user stats resource: {}", e);
                Err(serde_json::json!({
                    "code": -32001,
                    "message": "Failed to read resource"
                }))
            }
        },
        _ => Err(serde_json::json!({
            "code": -32001,
            "message": "Resource handler not implemented"
        })),
    }
}

async fn handle_prompt_get(name: &str, arguments: Option<&Value>) -> Result<Value, Value> {
    // First check if the prompt exists in our registry
    let _prompt = PROMPT_REGISTRY
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| {
            serde_json::json!({
                "code": -32003,
                "message": "Prompt not found"
            })
        })?;

    match name {
        "code_review" => {
            let code = arguments
                .and_then(|args| args.get("code"))
                .and_then(|v| v.as_str())
                .unwrap_or("// No code provided");

            let language = arguments
                .and_then(|args| args.get("language"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            Ok(serde_json::json!({
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Please review this {} code:\n\n{}", language, code)
                    }
                }]
            }))
        }
        "explain_error" => {
            let error = arguments
                .and_then(|args| args.get("error"))
                .and_then(|v| v.as_str())
                .unwrap_or("No error provided");

            Ok(serde_json::json!({
                "messages": [{
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": format!("Please explain this error and suggest how to fix it:\n\n{}", error)
                    }
                }]
            }))
        }
        _ => Err(serde_json::json!({
            "code": -32003,
            "message": "Prompt handler not implemented"
        })),
    }
}

fn get_tool_schema(tool_name: &str) -> Value {
    match tool_name {
        "text_length" => serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to measure"
                }
            },
            "required": ["text"]
        }),
        "text_transform" => serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to transform"
                },
                "transform": {
                    "type": "string",
                    "enum": ["uppercase", "lowercase", "titlecase"],
                    "description": "The transformation to apply"
                }
            },
            "required": ["text", "transform"]
        }),
        "text_search" => serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to search in"
                },
                "pattern": {
                    "type": "string",
                    "description": "The pattern to search for"
                }
            },
            "required": ["text", "pattern"]
        }),
        "timestamp" => serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        "ai_complete" => serde_json::json!({
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": "The prompt to complete"
                }
            },
            "required": ["prompt"]
        }),
        "ai_summarize" => serde_json::json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text to summarize"
                }
            },
            "required": ["text"]
        }),
        "user_stats" => serde_json::json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        }),
        _ => serde_json::json!({
            "type": "object",
            "additionalProperties": true
        }),
    }
}
