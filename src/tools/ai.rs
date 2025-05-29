use rig::completion::Prompt;
use rig::providers::openai;
use shuttle_runtime::SecretStore;

/// AI completion tool
pub async fn ai_complete(prompt: &str, secrets: &SecretStore) -> Option<String> {
    let api_key = secrets.get("OPENAI_API_KEY")?;
    // Set the API key in the environment for rig
    std::env::set_var("OPENAI_API_KEY", api_key);
    let openai_client = openai::Client::from_env();
    let agent = openai_client.agent("gpt-4").build();
    let response = agent.prompt(prompt).await.ok()?;
    Some(response)
}

/// AI summarize tool
pub async fn ai_summarize(text: &str, secrets: &SecretStore) -> Option<String> {
    let prompt = format!("Summarize the following text:\n{}", text);
    ai_complete(&prompt, secrets).await
}
