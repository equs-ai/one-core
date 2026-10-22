// &amp; &lt; &gt; &#xD;
pub(crate) fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

// &amp; &lt; &quot; &#x9; &#xA; &#xD;
pub(crate) fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            _ => out.push(ch),
        }
    }
    out
}

// &#xD;
pub(crate) fn escape_pi(s: &str) -> String {
    s.replace('\r', "&#xD;")
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn text_passthrough() {
        assert_eq!(escape_text("hello"), "hello");
    }

    #[test]
    fn text_entities() {
        assert_eq!(escape_text("a&b<c>d"), "a&amp;b&lt;c&gt;d");
    }

    #[test]
    fn text_carriage_return() {
        assert_eq!(escape_text("line\rend"), "line&#xD;end");
    }

    #[test]
    fn attr_passthrough() {
        assert_eq!(escape_attr("hello"), "hello");
    }

    #[test]
    fn attr_entities() {
        assert_eq!(escape_attr("a&b\"c"), "a&amp;b&quot;c");
    }

    #[test]
    fn attr_whitespace() {
        assert_eq!(escape_attr("a\tb\nc\rd"), "a&#x9;b&#xA;c&#xD;d");
    }

    #[test]
    fn pi_carriage_return() {
        assert_eq!(escape_pi("data\rhere"), "data&#xD;here");
    }

    #[test]
    fn pi_passthrough() {
        assert_eq!(escape_pi("normal text"), "normal text");
    }
}
