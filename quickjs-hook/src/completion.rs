//! JS 补全逻辑：为 REPL 提供 tab 补全候选项

use crate::JS_ENGINE;

/// Parse a JSON array of strings using a simple state machine.
/// Correctly handles `\"` and `\\` escape sequences inside string values.
/// Returns an empty vec on any parse error.
fn parse_json_string_array(json: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut chars = json.chars().peekable();

    // Consume leading whitespace and '['
    loop {
        match chars.peek() {
            Some(&c) if c.is_whitespace() || c == '[' => { chars.next(); }
            _ => break,
        }
    }

    loop {
        // Skip whitespace and commas between elements
        loop {
            match chars.peek() {
                Some(&c) if c.is_whitespace() || c == ',' => { chars.next(); }
                _ => break,
            }
        }

        match chars.peek() {
            None | Some(&']') => break,
            Some(&'"') => {
                chars.next(); // consume opening '"'
                let mut s = String::new();
                loop {
                    match chars.next() {
                        None => break, // malformed input
                        Some('\\') => match chars.next() {
                            Some('"') => s.push('"'),
                            Some('\\') => s.push('\\'),
                            Some('n') => s.push('\n'),
                            Some('r') => s.push('\r'),
                            Some('t') => s.push('\t'),
                            Some(c) => { s.push('\\'); s.push(c); }
                            None => break,
                        },
                        Some('"') => break, // end of string
                        Some(c) => s.push(c),
                    }
                }
                if !s.is_empty() {
                    result.push(s);
                }
            }
            _ => { chars.next(); } // skip unexpected characters
        }
    }

    result
}

/// Get completion candidates for a given prefix from the global JS engine.
///
/// Supports dot notation: if `prefix` contains a `.` (e.g. `"console.l"` or
/// `"Memory."`), the part before the last dot is evaluated as a JS expression
/// and properties of that object (including prototype chain) are enumerated.
/// Otherwise, properties of `globalThis` are enumerated.
///
/// Returns property names (never the full dotted path) so that the caller can
/// use the result as rustyline replacement candidates starting from after the dot.
/// Returns an empty vec if the engine is not initialised or on any error.
pub fn complete_script(prefix: &str) -> Vec<String> {
    let engine = match JS_ENGINE.lock() {
        Ok(g) => g,
        Err(_) => return vec![],
    };
    let engine = match engine.as_ref() {
        Some(e) => e,
        None => return vec![],
    };

    // Split on the last '.' to support multi-level paths like "a.b.c"
    let (script, prop_prefix) = if let Some(dot_pos) = prefix.rfind('.') {
        let obj_path = &prefix[..dot_pos];
        let prop_part = &prefix[dot_pos + 1..];

        // Escape the object path for safe embedding inside a JS string literal
        let escaped = obj_path
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r");

        let js = format!(
            r#"(function() {{
                var names = [];
                var obj;
                try {{
                    obj = eval("({escaped})");
                }} catch(e) {{
                    return JSON.stringify([]);
                }}
                if (obj === null || obj === undefined) {{
                    return JSON.stringify([]);
                }}
                var seen = {{}};
                var cur = obj;
                while (cur !== null && cur !== undefined) {{
                    try {{
                        var keys = Object.getOwnPropertyNames(cur);
                        for (var i = 0; i < keys.length; i++) {{
                            if (!seen[keys[i]]) {{
                                seen[keys[i]] = true;
                                names.push(keys[i]);
                            }}
                        }}
                    }} catch(e) {{}}
                    cur = Object.getPrototypeOf(cur);
                }}
                return JSON.stringify(names);
            }})()"#
        );
        (js, prop_part.to_string())
    } else {
        // No dot: enumerate globalThis
        let js = r#"(function() {
            var names = [];
            var obj = globalThis;
            while (obj !== null && obj !== undefined) {
                try {
                    var keys = Object.getOwnPropertyNames(obj);
                    for (var i = 0; i < keys.length; i++) { names.push(keys[i]); }
                } catch(e) {}
                obj = Object.getPrototypeOf(obj);
            }
            return JSON.stringify(names);
        })()"#
            .to_string();
        (js, prefix.to_string())
    };

    let result = match engine.eval(&script) {
        Ok(v) => v,
        Err(_) => return vec![],
    };

    let json_str = match result.to_string(engine.context().as_ptr()) {
        Some(s) => s,
        None => {
            result.free(engine.context().as_ptr());
            return vec![];
        }
    };
    result.free(engine.context().as_ptr());

    // Parse the JSON array using a state machine to correctly handle escape sequences
    // (split(',') would break on property names containing escaped quotes or backslashes)
    let prop_lower = prop_prefix.to_lowercase();
    let mut candidates: Vec<String> = parse_json_string_array(&json_str)
        .into_iter()
        .filter(|name| name.to_lowercase().starts_with(&prop_lower))
        .collect();

    // Deduplicate while preserving order
    candidates.sort();
    candidates.dedup();
    candidates
}
