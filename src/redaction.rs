use serde_json::Value;

const REDACTED: &str = "[redacted]";

pub fn redact_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let value = if is_sensitive_key(key) {
                        Value::String(REDACTED.to_string())
                    } else {
                        redact_json_value(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact_json_value).collect()),
        value => value.clone(),
    }
}

pub fn debug_payload_for_logging(value: &Value, log_full_payloads: bool) -> Value {
    if log_full_payloads {
        value.clone()
    } else {
        redact_json_value(value)
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|ch| *ch != '-' && *ch != '_')
        .flat_map(char::to_lowercase)
        .collect::<String>();

    matches!(
        normalized.as_str(),
        "authorization"
            | "apikey"
            | "apiaccesskey"
            | "accesstoken"
            | "authtoken"
            | "bearertoken"
            | "clientsecret"
            | "credential"
            | "credentials"
            | "password"
            | "secret"
            | "signingsecret"
            | "token"
            | "webhookurl"
    ) || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("apikey")
        || normalized.contains("authorization")
        || normalized.contains("credential")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_sensitive_keys_case_insensitively() {
        let payload = json!({
            "Authorization": "Bearer abc",
            "nested": {
                "api_key": "key-123",
                "normal": "kept",
                "client-secret": "secret-123"
            }
        });

        let redacted = redact_json_value(&payload);

        assert_eq!(redacted["Authorization"], REDACTED);
        assert_eq!(redacted["nested"]["api_key"], REDACTED);
        assert_eq!(redacted["nested"]["client-secret"], REDACTED);
        assert_eq!(redacted["nested"]["normal"], "kept");
    }

    #[test]
    fn redacts_sensitive_keys_inside_arrays() {
        let payload = json!({
            "alerts": [
                { "token": "one", "host": "host-a" },
                { "WEBHOOK_URL": "https://hooks.example.test/secret", "host": "host-b" }
            ]
        });

        let redacted = redact_json_value(&payload);

        assert_eq!(redacted["alerts"][0]["token"], REDACTED);
        assert_eq!(redacted["alerts"][0]["host"], "host-a");
        assert_eq!(redacted["alerts"][1]["WEBHOOK_URL"], REDACTED);
        assert_eq!(redacted["alerts"][1]["host"], "host-b");
    }

    #[test]
    fn full_payload_logging_switch_preserves_raw_payload() {
        let payload = json!({ "token": "raw-token" });

        assert_eq!(
            debug_payload_for_logging(&payload, false)["token"],
            REDACTED
        );
        assert_eq!(
            debug_payload_for_logging(&payload, true)["token"],
            "raw-token"
        );
    }
}
