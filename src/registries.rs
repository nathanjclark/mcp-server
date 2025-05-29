use once_cell::sync::Lazy;

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
}

pub struct Resource {
    pub uri: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub mime_type: &'static str,
}

pub struct Prompt {
    pub name: &'static str,
    pub description: &'static str,
    pub arguments: Vec<PromptArgument>,
}

pub struct PromptArgument {
    pub name: &'static str,
    pub description: &'static str,
    pub required: bool,
}

pub static TOOL_REGISTRY: Lazy<Vec<Tool>> = Lazy::new(|| {
    vec![
        Tool {
            name: "text_length",
            description: "Get the length of a string.",
        },
        Tool {
            name: "text_transform",
            description: "Transform text to uppercase, lowercase, or titlecase.",
        },
        Tool {
            name: "text_search",
            description: "Search for a substring in text.",
        },
        Tool {
            name: "timestamp",
            description: "Get the current UTC timestamp.",
        },
        Tool {
            name: "ai_complete",
            description: "Complete a prompt using an LLM.",
        },
        Tool {
            name: "ai_summarize",
            description: "Summarize text using an LLM.",
        },
        Tool {
            name: "user_stats",
            description: "Get summary statistics from the users table.",
        },
    ]
});

pub static RESOURCE_REGISTRY: Lazy<Vec<Resource>> = Lazy::new(|| {
    vec![Resource {
        uri: "user://stats",
        name: "User Statistics",
        description: "Current user statistics from the database",
        mime_type: "application/json",
    }]
});

pub static PROMPT_REGISTRY: Lazy<Vec<Prompt>> = Lazy::new(|| {
    vec![
        Prompt {
            name: "code_review",
            description: "Generate a code review prompt",
            arguments: vec![
                PromptArgument {
                    name: "code",
                    description: "The code to review",
                    required: true,
                },
                PromptArgument {
                    name: "language",
                    description: "Programming language",
                    required: false,
                },
            ],
        },
        Prompt {
            name: "explain_error",
            description: "Generate a prompt to explain an error",
            arguments: vec![PromptArgument {
                name: "error",
                description: "The error message",
                required: true,
            }],
        },
    ]
});
