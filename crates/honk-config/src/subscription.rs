use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::SubscriptionType;

/// Rejection message for a URL that is neither remote `http(s)` nor local `file:`.
const SUBSCRIPTION_URL_UNSUPPORTED: &str =
    "subscription URL must use http://, https://, or file://";
/// Rejection message for a `file:` URL that cannot name exactly one local file.
const SUBSCRIPTION_URL_MALFORMED_FILE: &str = "invalid local file subscription URL";

/// How a subscription URL is obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionLocation {
    /// An `http://` or `https://` URL fetched over the network.
    Remote,
    /// A `file:` URL resolved to a local path.
    Local(PathBuf),
}

/// Classify a subscription URL as remote or local.
///
/// `file:` accepts an absolute `file:///path`, a `file://localhost/path`, and
/// dae's legacy `file://relative/path`, whose authority becomes the first
/// segment of a relative path. Credentials, a query, a fragment, and a URL
/// with no final path component are rejected here, so a URL that reaches a
/// reader always names one local file.
pub fn subscription_location(url: &str) -> Result<SubscriptionLocation, &'static str> {
    if url.starts_with("http://") || url.starts_with("https://") {
        return Ok(SubscriptionLocation::Remote);
    }
    if !url.starts_with("file:") {
        return Err(SUBSCRIPTION_URL_UNSUPPORTED);
    }
    let parsed = url::Url::parse(url).map_err(|_| SUBSCRIPTION_URL_MALFORMED_FILE)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SUBSCRIPTION_URL_MALFORMED_FILE);
    }
    if let Ok(path) = parsed.to_file_path()
        && path.file_name().is_some()
    {
        return Ok(SubscriptionLocation::Local(path));
    }
    let mut path = PathBuf::new();
    if let Some(host) = parsed.host_str() {
        path.push(host);
    }
    for segment in parsed.path_segments().into_iter().flatten() {
        if segment.is_empty() {
            continue;
        }
        // `path_segments` is percent-encoded; only `to_file_path` decodes it.
        path.push(
            percent_encoding::percent_decode_str(segment)
                .decode_utf8_lossy()
                .as_ref(),
        );
    }
    if path.file_name().is_none() {
        return Err(SUBSCRIPTION_URL_MALFORMED_FILE);
    }
    Ok(SubscriptionLocation::Local(path))
}

/// A proxy subscription (e.g., subscription link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub sub_type: SubscriptionType,
    /// Update interval in seconds (0 = manual)
    #[serde(default = "default_update_interval")]
    pub update_interval: u64,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub headers: Vec<SubscriptionHeader>,
    #[serde(default = "crate::types::default_true")]
    pub enabled: bool,
    /// Last update time
    #[serde(default)]
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of nodes from this subscription
    #[serde(default)]
    pub node_count: u32,
    /// Created at
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
}

fn default_update_interval() -> u64 {
    86400 // 24 hours
}

impl Default for Subscription {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            url: String::new(),
            sub_type: SubscriptionType::default(),
            update_interval: default_update_interval(),
            user_agent: None,
            headers: Vec::new(),
            enabled: true,
            last_updated: None,
            node_count: 0,
            created_at: Utc::now(),
        }
    }
}

/// Custom HTTP header for subscription fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionHeader {
    pub key: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_remote_and_local_subscription_urls() {
        for url in ["https://example.com/sub", "http://example.com/sub"] {
            assert_eq!(
                subscription_location(url),
                Ok(SubscriptionLocation::Remote),
                "{url}"
            );
        }
        for (url, path) in [
            ("file:///etc/honk/local.sub", "/etc/honk/local.sub"),
            ("file://localhost/etc/honk/local.sub", "/etc/honk/local.sub"),
            (
                "file://relative/path/to/mysub.sub",
                "relative/path/to/mysub.sub",
            ),
            ("file://relative/a%20b.sub", "relative/a b.sub"),
            ("file://relative", "relative"),
        ] {
            assert_eq!(
                subscription_location(url),
                Ok(SubscriptionLocation::Local(PathBuf::from(path))),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_other_schemes() {
        for url in [
            "ftp://example.com/sub",
            "http-file://example.com/sub",
            "https-file://example.com/sub",
            "example.com/sub",
        ] {
            assert_eq!(
                subscription_location(url),
                Err(SUBSCRIPTION_URL_UNSUPPORTED),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_malformed_file_urls() {
        for url in [
            "file://",
            "file:",
            "file:///",
            "file://user:pass@host/local.sub",
            "file:///etc/honk/local.sub?token=secret",
            "file:///etc/honk/local.sub#fragment",
        ] {
            assert_eq!(
                subscription_location(url),
                Err(SUBSCRIPTION_URL_MALFORMED_FILE),
                "{url}"
            );
        }
    }
}
