//! `locations` command: list Azure regions and their paired region, straight
//! from ARM so the list always reflects what the subscription can use.

use anyhow::Result;
use serde_json::{json, Value};

use crate::auth::Context;
use crate::{arm, output, OutputFormat};

/// Case-insensitive glob match with the same pattern semantics as `search`:
/// no `*` is a substring match; `*` wildcards anchor (`foo*` prefix, `*foo`
/// suffix, `f*o` matches segments in order).
pub fn name_matches(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let name = name.to_lowercase();
    if !pattern.contains('*') {
        return name.contains(&pattern);
    }
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let segments: Vec<&str> = pattern.split('*').filter(|s| !s.is_empty()).collect();

    let mut pos = 0;
    for (i, seg) in segments.iter().enumerate() {
        match name[pos..].find(seg) {
            Some(offset) if i == 0 && anchored_start && offset != 0 => return false,
            Some(offset) => pos = pos + offset + seg.len(),
            None => return false,
        }
    }
    if anchored_end {
        match segments.last() {
            Some(last) => name.ends_with(last) && pos == name.len(),
            None => false, // pattern was only `*`s with anchored end: unreachable
        }
    } else {
        true
    }
}

/// Project one ARM location entry into an output row. Logical regions (e.g.
/// geography groups) are skipped; physical regions without a pair (newer
/// zone-redundant-only regions) get a null pair, rendered as `-`.
pub fn to_row(loc: &Value) -> Option<Value> {
    let region_type = loc.pointer("/metadata/regionType").and_then(Value::as_str);
    if region_type != Some("Physical") {
        return None;
    }
    let name = loc.get("name").and_then(Value::as_str)?;
    Some(json!({
        "name": name,
        "displayName": loc.get("displayName").and_then(Value::as_str),
        "geography": loc.pointer("/metadata/geography").and_then(Value::as_str),
        "pairedRegion": loc
            .pointer("/metadata/pairedRegion/0/name")
            .and_then(Value::as_str),
    }))
}

pub async fn list(ctx: &Context, name: Option<&str>, fmt: OutputFormat) -> Result<()> {
    let locations = arm::list_locations(ctx).await?;
    let mut rows: Vec<Value> = locations
        .iter()
        .filter_map(to_row)
        .filter(|row| match name {
            Some(pattern) => row
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| name_matches(pattern, n)),
            None => true,
        })
        .collect();
    rows.sort_by(|a, b| {
        let key = |r: &Value| {
            (
                r.get("geography")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                r.get("name").and_then(Value::as_str).map(str::to_string),
            )
        };
        key(a).cmp(&key(b))
    });

    match fmt {
        OutputFormat::Json => output::print_json(&json!(rows)),
        OutputFormat::Table => {
            if rows.is_empty() {
                println!("No matching regions found.");
            } else {
                output::print_table(
                    &["NAME", "DISPLAY NAME", "GEOGRAPHY", "PAIRED REGION"],
                    &rows,
                    &["name", "displayName", "geography", "pairedRegion"],
                );
                println!("\n{} region(s).", rows.len());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{name_matches, to_row};
    use serde_json::json;

    #[test]
    fn plain_pattern_is_substring_case_insensitive() {
        assert!(name_matches("east", "eastus"));
        assert!(name_matches("EAST", "southeastasia"));
        assert!(!name_matches("west", "eastus"));
    }

    #[test]
    fn trailing_star_is_prefix() {
        assert!(name_matches("east*", "eastus2"));
        assert!(!name_matches("east*", "southeastasia"));
    }

    #[test]
    fn leading_star_is_suffix() {
        assert!(name_matches("*us", "eastus"));
        assert!(!name_matches("*us", "eastus2"));
    }

    #[test]
    fn internal_star_matches_segments_in_order() {
        assert!(name_matches("east*2", "eastus2"));
        assert!(!name_matches("east*2", "eastus"));
        assert!(!name_matches("2*east", "eastus2"));
    }

    #[test]
    fn physical_region_projects_pair() {
        let row = to_row(&json!({
            "name": "eastus",
            "displayName": "East US",
            "metadata": {
                "regionType": "Physical",
                "geography": "United States",
                "pairedRegion": [{ "name": "westus" }],
            },
        }))
        .unwrap();
        assert_eq!(row["name"], "eastus");
        assert_eq!(row["displayName"], "East US");
        assert_eq!(row["geography"], "United States");
        assert_eq!(row["pairedRegion"], "westus");
    }

    #[test]
    fn unpaired_physical_region_has_null_pair() {
        let row = to_row(&json!({
            "name": "polandcentral",
            "displayName": "Poland Central",
            "metadata": { "regionType": "Physical", "geography": "Poland" },
        }))
        .unwrap();
        assert_eq!(row["pairedRegion"], serde_json::Value::Null);
    }

    #[test]
    fn logical_regions_are_skipped() {
        assert!(to_row(&json!({
            "name": "unitedstates",
            "displayName": "United States",
            "metadata": { "regionType": "Logical" },
        }))
        .is_none());
    }
}
