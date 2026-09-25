use axum::http::{HeaderMap, HeaderValue, header};
use cloudevents::event::{AttributeValue, SpecVersion};
use cloudevents::{AttributesReader, Data};
use serde_json::{Map, Number, Value};

const STRUCTURED_JSON_MEDIA_TYPE: &str = "application/cloudevents+json";
const BATCH_JSON_MEDIA_TYPE: &str = "application/cloudevents-batch+json";

#[derive(Debug, Clone, PartialEq)]
pub struct DecodedCloudEvent {
    pub source: String,
    pub id: String,
    pub envelope: Value,
}

impl DecodedCloudEvent {
    pub fn occurrence_id(&self) -> String {
        format!(
            "cloudevents:{}:{}:{}:{}",
            self.source.len(),
            self.source,
            self.id.len(),
            self.id
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CloudEventsError {
    #[error("malformed CloudEvent: {0}")]
    Malformed(&'static str),
    #[error("unsupported CloudEvents media or encoding: {0}")]
    UnsupportedMediaType(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentMode {
    Structured,
    Binary,
}

pub fn decode(headers: &HeaderMap, body: &[u8]) -> Result<DecodedCloudEvent, CloudEventsError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(|value| {
            value
                .to_str()
                .map_err(|_| CloudEventsError::UnsupportedMediaType("invalid Content-Type header"))
        })
        .transpose()?;
    let media_type = content_type.map(base_media_type);

    let mode = match media_type.as_deref() {
        Some(BATCH_JSON_MEDIA_TYPE) => {
            return Err(CloudEventsError::UnsupportedMediaType(
                "batch mode is not supported",
            ));
        }
        Some(STRUCTURED_JSON_MEDIA_TYPE) => ContentMode::Structured,
        _ if headers.contains_key("ce-specversion") => {
            let Some(media_type) = media_type.as_deref() else {
                return Err(CloudEventsError::UnsupportedMediaType(
                    "binary mode requires a JSON Content-Type",
                ));
            };
            if !is_json_media_type(media_type) {
                return Err(CloudEventsError::UnsupportedMediaType(
                    "binary event data must use a JSON Content-Type",
                ));
            }
            ContentMode::Binary
        }
        _ => {
            return Err(CloudEventsError::UnsupportedMediaType(
                "expected structured JSON or binary JSON mode",
            ));
        }
    };

    let mut sdk_headers = headers.clone();
    if mode == ContentMode::Structured {
        sdk_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(STRUCTURED_JSON_MEDIA_TYPE),
        );
    }

    let event = cloudevents::binding::http::to_event(&sdk_headers, body.to_vec())
        .map_err(|_| CloudEventsError::Malformed("invalid CloudEvents message"))?;

    if event.specversion() != SpecVersion::V10 {
        return Err(CloudEventsError::Malformed(
            "only CloudEvents specversion 1.0 is supported",
        ));
    }

    if event.id().is_empty() || event.source().is_empty() || event.ty().is_empty() {
        return Err(CloudEventsError::Malformed(
            "id, source, and type must be non-empty",
        ));
    }

    if event.data().is_some()
        && event
            .datacontenttype()
            .map(base_media_type)
            .is_some_and(|media_type| !is_json_media_type(&media_type))
    {
        return Err(CloudEventsError::UnsupportedMediaType(
            "event data must be JSON",
        ));
    }

    let source = event.source().as_str().to_string();
    let id = event.id().to_string();
    let mut envelope = Map::new();
    for (name, value) in event.iter() {
        envelope.insert(name.to_string(), attribute_to_json(value));
    }

    if let Some(data) = event.data() {
        envelope.insert("data".to_string(), data_to_json(data)?);
    }

    Ok(DecodedCloudEvent {
        source,
        id,
        envelope: Value::Object(envelope),
    })
}

fn base_media_type(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn is_json_media_type(media_type: &str) -> bool {
    matches!(media_type, "application/json" | "text/json") || media_type.ends_with("+json")
}

fn data_to_json(data: &Data) -> Result<Value, CloudEventsError> {
    match data {
        Data::Json(value) => Ok(value.clone()),
        Data::Binary(bytes) => serde_json::from_slice(bytes)
            .map_err(|_| CloudEventsError::Malformed("event data is not valid JSON")),
        Data::String(_) => Err(CloudEventsError::UnsupportedMediaType(
            "event data must be JSON",
        )),
    }
}

fn attribute_to_json(value: AttributeValue<'_>) -> Value {
    match value {
        AttributeValue::Boolean(value) => Value::Bool(*value),
        AttributeValue::Integer(value) => Value::Number(Number::from(*value)),
        AttributeValue::String(value) => Value::String(value.to_string()),
        AttributeValue::Binary(value) => Value::String(AttributeValue::Binary(value).to_string()),
        AttributeValue::URI(value) => Value::String(value.as_str().to_string()),
        AttributeValue::URIRef(value) => Value::String(value.as_str().to_string()),
        AttributeValue::Time(value) => Value::String(value.to_rfc3339()),
        AttributeValue::SpecVersion(value) => Value::String(value.as_str().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binary_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert("ce-specversion", HeaderValue::from_static("1.0"));
        headers.insert("ce-id", HeaderValue::from_static("event-1"));
        headers.insert("ce-source", HeaderValue::from_static("urn:test:alerts"));
        headers.insert("ce-type", HeaderValue::from_static("com.example.alert"));
        headers.insert("ce-subject", HeaderValue::from_static("service/api"));
        headers.insert("ce-tenant", HeaderValue::from_static("platform"));
        headers
    }

    #[test]
    fn structured_and_binary_json_decode_to_the_same_envelope() {
        let mut structured_headers = HeaderMap::new();
        structured_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("Application/CloudEvents+Json; charset=utf-8"),
        );
        let structured = decode(
            &structured_headers,
            &serde_json::to_vec(&json!({
                "specversion": "1.0",
                "id": "event-1",
                "source": "urn:test:alerts",
                "type": "com.example.alert",
                "subject": "service/api",
                "tenant": "platform",
                "datacontenttype": "application/json",
                "data": {"status": "firing", "title": "API is down"}
            }))
            .unwrap(),
        )
        .unwrap();
        let binary = decode(
            &binary_headers(),
            &serde_json::to_vec(&json!({"status": "firing", "title": "API is down"})).unwrap(),
        )
        .unwrap();

        assert_eq!(structured, binary);
        assert_eq!(structured.envelope["tenant"], "platform");
        assert_eq!(structured.envelope["data"]["status"], "firing");
        assert_eq!(
            structured.occurrence_id(),
            "cloudevents:15:urn:test:alerts:7:event-1"
        );
    }

    #[test]
    fn preserves_typed_structured_extensions() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(STRUCTURED_JSON_MEDIA_TYPE),
        );
        let decoded = decode(
            &headers,
            br#"{"specversion":"1.0","id":"1","source":"urn:test","type":"test","attempt":2,"urgent":true,"data":null}"#,
        )
        .unwrap();

        assert_eq!(decoded.envelope["attempt"], 2);
        assert_eq!(decoded.envelope["urgent"], true);
        assert!(decoded.envelope["data"].is_null());
    }

    #[test]
    fn rejects_unsupported_version_and_missing_required_attributes() {
        let mut headers = binary_headers();
        headers.insert("ce-specversion", HeaderValue::from_static("0.3"));
        assert!(matches!(
            decode(&headers, br#"{}"#),
            Err(CloudEventsError::Malformed(_))
        ));

        let mut missing_id = binary_headers();
        missing_id.remove("ce-id");
        assert!(matches!(
            decode(&missing_id, br#"{}"#),
            Err(CloudEventsError::Malformed(_))
        ));

        let mut empty_id = binary_headers();
        empty_id.insert("ce-id", HeaderValue::from_static(""));
        assert!(matches!(
            decode(&empty_id, br#"{}"#),
            Err(CloudEventsError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_unsupported_encodings_and_malformed_json_data() {
        let mut batch_headers = HeaderMap::new();
        batch_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(BATCH_JSON_MEDIA_TYPE),
        );
        assert!(matches!(
            decode(&batch_headers, br#"[]"#),
            Err(CloudEventsError::UnsupportedMediaType(_))
        ));

        let mut text_headers = binary_headers();
        text_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(matches!(
            decode(&text_headers, b"not json"),
            Err(CloudEventsError::UnsupportedMediaType(_))
        ));

        assert!(matches!(
            decode(&binary_headers(), b"not json"),
            Err(CloudEventsError::Malformed(_))
        ));

        let json_only = HeaderMap::from_iter([(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )]);
        assert!(matches!(
            decode(&json_only, br#"{}"#),
            Err(CloudEventsError::UnsupportedMediaType(_))
        ));
    }
}
