use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub struct OpenAICreds {
    pub api_key: String,
    pub org_id: Option<String>,
    pub project_id: Option<String>,
}

#[derive(Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Deserialize)]
struct Choice {
    message: MessageContent,
}

#[derive(Deserialize)]
struct MessageContent {
    content: String,
}

pub async fn validate_vulnerabilities_with_gpt(
    openai_creds: &OpenAICreds,
    findings_by_file: &[(usize, String, String, String)],
    file_content: &str,
    language: &str,
    validate_all_severities: bool,
) -> Result<(String, String), Box<dyn Error>> {
    let client = Client::new();

    let mut findings_list = String::new();
    for (line_number, vulnerability_id, severity, _) in findings_by_file {
        if validate_all_severities || severity == "Critical" || severity == "High" {
            findings_list.push_str(&format!("line {}: {}\n", line_number, vulnerability_id));
        }
    }

    let prompt = match language {
        "Rust" => format!(
            "A SAST tool detects potential Rust vulnerabilities in the following file:\n\nSource code:\n{}\n\nFindings list:\n{}\n\nAre these valid vulnerabilities or false positives? Provide an explanation.",
            file_content, findings_list
        ),
        "Solidity-Ethereum" => format!(
            "A SAST tool detects potential Solidity vulnerabilities in the following file:\n\nSource code:\n{}\n\nFindings list:\n{}\n\nAre these valid vulnerabilities or false positives? Provide an explanation.",
            file_content, findings_list
        ),
        _ => return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unsupported language"))),
    };

    let chat_request = ChatRequest {
        model: "gpt-3.5-turbo".to_string(),
        messages: vec![Message {
            role: "user".to_string(),
            content: prompt,
        }],
    };

    let mut response = client
        .post("https://api.openai.com/v1/chat/completions")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", openai_creds.api_key));
    if let Some(org) = &openai_creds.org_id {
        response = response.header("OpenAI-Organization", org);
    }
    if let Some(project) = &openai_creds.project_id {
        response = response.header("OpenAI-Project", project);
    }
    let response = response.json(&chat_request).send().await?;

    if response.status().is_success() {
        let chat_response = response.json::<ChatResponse>().await?;
        let text = chat_response
            .choices
            .get(0)
            .map_or_else(|| "", |choice| &choice.message.content);

        let status = analyze_response_text(&text);

        Ok((status.to_string(), "".to_string()))
    } else {
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to get a valid response from OpenAI",
        )))
    }
}

fn analyze_response_text(text: &str) -> &str {
    if text.contains("not a vulnerability")
        || text.contains("is not a valid vulnerability")
        || text
            .to_lowercase()
            .contains("appears to be a false positive")
        || text.to_lowercase().contains("is no vulnerability present")
        || text.to_lowercase().contains("is a false positive")
        || text.to_lowercase().contains("likely a false positive")
        || text.to_lowercase().contains("may be a false positive")
        || text.to_lowercase().contains("seems to be a false positive")
        || text.to_lowercase().contains("most likely a false positive")
        || text
            .to_lowercase()
            .contains("does not contain a vulnerability")
        || text
            .to_lowercase()
            .contains("not appear to have a potential vulnerability")
        || text
            .to_lowercase()
            .contains("does not seem to have any obvious vulnerability")
        || text
            .to_lowercase()
            .contains("does not introduce a vulnerability")
        || text
            .to_lowercase()
            .contains("not suggest any security issues")
        || text
            .to_lowercase()
            .contains("does not appear to be vulnerable")
        || text
            .to_lowercase()
            .contains("does not appear to have any clear vulnerability")
        || text
            .to_lowercase()
            .contains("does not appear to have any potential vulnerability")
        || text.to_lowercase().contains("is not valid in this case")
        || text.to_lowercase().contains("does not appear to be valid")
        || text
            .to_lowercase()
            .contains("does not appear to contain any potential vulnerability")
        || text.is_empty()
    {
        "False positive"
    } else {
        "Valid"
    }
}
