use once_cell::sync::Lazy;

pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
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

pub mod ai;
pub mod db;
pub mod text;
pub mod utils;
