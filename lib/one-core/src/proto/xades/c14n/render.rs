use super::escape;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NsDecl {
    pub prefix: String,
    pub uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attr {
    pub ns_uri: String,
    pub local_name: String,
    pub qualified_name: String,
    pub value: String,
}

impl NsDecl {
    pub fn render(&self) -> String {
        if self.prefix.is_empty() {
            format!(" xmlns=\"{}\"", escape::escape_attr(&self.uri))
        } else {
            format!(
                " xmlns:{}=\"{}\"",
                self.prefix,
                escape::escape_attr(&self.uri)
            )
        }
    }
}

impl Ord for NsDecl {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.prefix.is_empty(), other.prefix.is_empty()) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => self.prefix.cmp(&other.prefix),
        }
    }
}

impl PartialOrd for NsDecl {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Attr {
    pub fn render(&self) -> String {
        format!(
            " {}=\"{}\"",
            self.qualified_name,
            escape::escape_attr(&self.value)
        )
    }
}

impl Ord for Attr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self.ns_uri.is_empty(), other.ns_uri.is_empty()) {
            (true, true) => self.local_name.cmp(&other.local_name),
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => self
                .ns_uri
                .cmp(&other.ns_uri)
                .then(self.local_name.cmp(&other.local_name)),
        }
    }
}

impl PartialOrd for Attr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn ns_decl_default_renders_xmlns() {
        let ns = NsDecl {
            prefix: String::new(),
            uri: "http://example.com".into(),
        };
        assert_eq!(ns.render(), " xmlns=\"http://example.com\"");
    }

    #[test]
    fn ns_decl_prefixed_renders_xmlns_prefix() {
        let ns = NsDecl {
            prefix: "ds".into(),
            uri: "http://www.w3.org/2000/09/xmldsig#".into(),
        };
        assert_eq!(
            ns.render(),
            " xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\""
        );
    }

    #[test]
    fn ns_decl_empty_uri_renders_empty() {
        let ns = NsDecl {
            prefix: String::new(),
            uri: String::new(),
        };
        assert_eq!(ns.render(), " xmlns=\"\"");
    }

    #[test]
    fn ns_decl_sort_default_first() {
        let default_ns = NsDecl {
            prefix: String::new(),
            uri: "http://a".into(),
        };
        let prefixed = NsDecl {
            prefix: "a".into(),
            uri: "http://b".into(),
        };
        assert!(default_ns < prefixed);
    }

    #[test]
    fn ns_decl_sort_by_prefix() {
        let a = NsDecl {
            prefix: "aaa".into(),
            uri: "http://z".into(),
        };
        let b = NsDecl {
            prefix: "zzz".into(),
            uri: "http://a".into(),
        };
        assert!(a < b);
    }

    #[test]
    fn attr_render_simple() {
        let attr = Attr {
            ns_uri: String::new(),
            local_name: "id".into(),
            qualified_name: "id".into(),
            value: "foo".into(),
        };
        assert_eq!(attr.render(), " id=\"foo\"");
    }

    #[test]
    fn attr_render_escapes_value() {
        let attr = Attr {
            ns_uri: String::new(),
            local_name: "val".into(),
            qualified_name: "val".into(),
            value: "a&b\"c".into(),
        };
        assert_eq!(attr.render(), " val=\"a&amp;b&quot;c\"");
    }

    #[test]
    fn attr_sort_no_ns_before_ns() {
        let plain = Attr {
            ns_uri: String::new(),
            local_name: "zzz".into(),
            qualified_name: "zzz".into(),
            value: String::new(),
        };
        let namespaced = Attr {
            ns_uri: "http://a".into(),
            local_name: "aaa".into(),
            qualified_name: "x:aaa".into(),
            value: String::new(),
        };
        assert!(plain < namespaced);
    }

    #[test]
    fn attr_sort_by_ns_uri_then_local() {
        let a = Attr {
            ns_uri: "http://a".into(),
            local_name: "z".into(),
            qualified_name: "p1:z".into(),
            value: String::new(),
        };
        let b = Attr {
            ns_uri: "http://b".into(),
            local_name: "a".into(),
            qualified_name: "p2:a".into(),
            value: String::new(),
        };
        assert!(a < b);
    }

    #[test]
    fn attr_sort_same_ns_by_local() {
        let a = Attr {
            ns_uri: "http://x".into(),
            local_name: "alpha".into(),
            qualified_name: "p:alpha".into(),
            value: String::new(),
        };
        let b = Attr {
            ns_uri: "http://x".into(),
            local_name: "beta".into(),
            qualified_name: "p:beta".into(),
            value: String::new(),
        };
        assert!(a < b);
    }
}
