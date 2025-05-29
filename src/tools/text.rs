pub fn text_length(text: &str) -> usize {
    text.chars().count()
}

pub fn text_transform(text: &str, transform: &str) -> Option<String> {
    match transform {
        "uppercase" => Some(text.to_uppercase()),
        "lowercase" => Some(text.to_lowercase()),
        "titlecase" => Some(
            text.split_whitespace()
                .map(|w| {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
        ),
        _ => None,
    }
}

pub fn text_search(text: &str, pattern: &str) -> bool {
    text.contains(pattern)
}
