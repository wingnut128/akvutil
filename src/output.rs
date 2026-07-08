//! Minimal table / JSON output helpers (no extra dependencies).

use serde_json::Value;

pub fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

/// Render a value for display.
pub fn display(v: &Value) -> String {
    match v {
        Value::Null => "-".to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Print rows of JSON objects as an aligned table.
pub fn print_table(headers: &[&str], rows: &[Value], keys: &[&str]) {
    if rows.is_empty() {
        println!("(no results)");
        return;
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| keys.iter().map(|k| display(&row[*k])).collect())
        .collect();

    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &cells {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let line = |cols: &[String]| {
        cols.iter()
            .enumerate()
            .map(|(i, c)| format!("{:<w$}", c, w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
    };

    println!(
        "{}",
        line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>())
    );
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("  ")
    );
    for row in &cells {
        println!("{}", line(row));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn display_renders_each_json_kind() {
        assert_eq!(display(&Value::Null), "-");
        // Strings render bare, without surrounding quotes.
        assert_eq!(display(&json!("hello")), "hello");
        assert_eq!(display(&json!(true)), "true");
        assert_eq!(display(&json!(42)), "42");
    }
}
