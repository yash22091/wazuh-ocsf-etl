use serde_json::Value;

// ─── JSON navigation helpers ──────────────────────────────────────────────────

/// Navigate a dotted path `"win.eventdata.ipAddress"` through a JSON tree.
/// Returns `""` if any segment is missing or the leaf is not a string.
pub(crate) fn jpath<'a>(root: &'a Value, path: &str) -> &'a str {
    let mut cur = root;
    for key in path.split('.') {
        match cur.as_object().and_then(|m| m.get(key)) {
            Some(v) => cur = v,
            None    => return "",
        }
    }
    cur.as_str().unwrap_or("")
}

/// Coerce a JSON scalar (String, Number, Bool) to a String.
/// Arrays and objects are ignored (return empty).
pub(crate) fn value_to_str(v: &Value) -> String {
    match v {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Number(n)                  => n.to_string(),
        Value::Bool(b)                    => b.to_string(),
        _                                 => String::new(),
    }
}

/// Scan `paths`; return first non-empty string found.
///
/// Lookup order per path:
/// 1. **Literal key** — `root["audit.exe"]` (some Wazuh agents/decoders flatten to
///    dotted literal keys instead of nesting).
/// 2. **Nested path** — split on `.` and navigate the JSON hierarchy.
pub(crate) fn first_str(root: &Value, paths: &[&str]) -> String {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(v) = obj.get(p) {
                if let Some(s) = v.as_str() {
                    if !s.is_empty() { return s.to_string(); }
                }
                continue;
            }
        }
        // 2. Navigate nested path
        let s = jpath(root, p);
        if !s.is_empty() { return s.to_string(); }
    }
    String::new()
}

/// Scan `paths` for a port value; handles both `"8080"` (string) and `8080` (number).
/// Tries literal key lookup first, then nested path navigation.
pub(crate) fn first_port(root: &Value, paths: &[&str]) -> u16 {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(val) = obj.get(p) {
                let v = match val {
                    Value::Number(n) => n.as_u64().map(|v| v.min(65535) as u16),
                    Value::String(s) => s.trim().parse::<u16>().ok(),
                    _                => None,
                };
                if let Some(port) = v { if port > 0 { return port; } }
                continue;
            }
        }
        // 2. Navigate nested path
        let mut cur = root;
        let mut ok = true;
        for key in p.split('.') {
            match cur.as_object().and_then(|m| m.get(key)) {
                Some(v) => cur = v,
                None    => { ok = false; break; }
            }
        }
        if !ok { continue; }
        let v = match cur {
            Value::Number(n) => n.as_u64().map(|v| v.min(65535) as u16),
            Value::String(s) => s.trim().parse::<u16>().ok(),
            _                => None,
        };
        if let Some(p) = v { if p > 0 { return p; } }
    }
    0
}

/// Scan `paths` for a u64 byte counter; handles both string and number.
/// Tries literal key lookup first, then nested path navigation.
pub(crate) fn first_u64(root: &Value, paths: &[&str]) -> u64 {
    for &p in paths {
        // 1. Try literal key first
        if let Some(obj) = root.as_object() {
            if let Some(val) = obj.get(p) {
                let v = match val {
                    Value::Number(n) => n.as_u64(),
                    Value::String(s) => s.trim().parse::<u64>().ok(),
                    _                => None,
                };
                if let Some(n) = v { return n; }
                continue;
            }
        }
        // 2. Navigate nested path
        let mut cur = root;
        let mut ok = true;
        for key in p.split('.') {
            match cur.as_object().and_then(|m| m.get(key)) {
                Some(v) => cur = v,
                None    => { ok = false; break; }
            }
        }
        if !ok { continue; }
        let v = match cur {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.trim().parse::<u64>().ok(),
            _                => None,
        };
        if let Some(n) = v { return n; }
    }
    0
}

/// Look up `field` inside the Wazuh `data` sub-object and return its value as a
/// String — works for **strings, numbers and booleans**.  Two strategies in order:
///
/// 1. **Literal key** — `data["audit.command"]` (flattened dotted key).
/// 2. **Nested path** — split on `.` and walk the JSON tree.
pub(crate) fn get_data_field(data: &Value, field: &str) -> String {
    // 1. Try literal key first
    if let Some(obj) = data.as_object() {
        if let Some(v) = obj.get(field) {
            let s = value_to_str(v);
            if !s.is_empty() { return s; }
        }
    }
    // 2. Navigate nested path
    let mut cur = data;
    for key in field.split('.') {
        match cur.as_object().and_then(|m| m.get(key)) {
            Some(v) => cur = v,
            None    => return String::new(),
        }
    }
    value_to_str(cur)
}

/// Recursively walk `val` and emit every leaf as a `(dotted_path, value_string)` pair.
/// `prefix` carries the path built so far (empty string at the root call).
pub(crate) fn flatten_to_paths(val: &Value, prefix: &str, out: &mut Vec<(String, String)>) {
    match val {
        Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_to_paths(v, &path, out);
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let path = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{prefix}.{i}")
                };
                flatten_to_paths(v, &path, out);
            }
        }
        Value::Null => {}
        leaf => {
            if !prefix.is_empty() {
                out.push((prefix.to_string(), value_to_str(leaf)));
            }
        }
    }
}
