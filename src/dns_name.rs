//! DNS identities preserve label boundaries and fold only ASCII case.

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CanonicalName(String);

impl CanonicalName {
    pub(crate) fn new(name: &str) -> Self {
        let labels = labels(name);
        let mut canonical = String::new();
        for label in labels {
            append_escaped_label(&mut canonical, &label.to_ascii_lowercase());
            canonical.push('.');
        }
        if canonical.is_empty() {
            canonical.push('.');
        }
        Self(canonical)
    }
}

pub(crate) fn names_equal(first: &str, second: &str) -> bool {
    CanonicalName::new(first) == CanonicalName::new(second)
}

/// Decodes the dot and backslash escapes accepted by the public name APIs.
pub(crate) fn labels(name: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut chars = name.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if chars
                    .peek()
                    .is_some_and(|next| *next == '.' || *next == '\\')
                {
                    if let Some(escaped) = chars.next() {
                        label.push(escaped);
                    }
                } else {
                    label.push(ch);
                }
            }
            '.' => {
                if !label.is_empty() {
                    labels.push(std::mem::take(&mut label));
                }
            }
            _ => label.push(ch),
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    labels
}

pub(crate) fn append_escaped_label(name: &mut String, label: &str) {
    for ch in label.chars() {
        if ch == '.' || ch == '\\' {
            name.push('\\');
        }
        name.push(ch);
    }
}

#[cfg(test)]
mod tests {
    use super::{names_equal, CanonicalName};

    #[test]
    fn canonical_names_preserve_labels_and_unicode_bytes() {
        assert!(names_equal("Printer.LOCAL", "printer.local."));
        assert!(names_equal(r"A\.B.local.", r"a\.b.LOCAL."));
        assert!(!names_equal(r"A\.B.local.", "a.b.local."));
        assert!(!names_equal("\u{c4}.local.", "\u{e4}.local."));
        assert_eq!(CanonicalName::new(""), CanonicalName::new("."));
        assert_eq!(
            CanonicalName::new(r"A\q.local."),
            CanonicalName::new(r"a\\q.local.")
        );
        assert_ne!(
            CanonicalName::new(r"\046.local."),
            CanonicalName::new(r"\..local.")
        );
    }
}
