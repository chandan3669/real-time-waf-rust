use config::{Config, ConfigError, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct WafConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub url: String,
    pub timeout_seconds: u64,
}

impl WafConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let builder = Config::builder()
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8000)?
            .set_default("upstream.url", "http://127.0.0.1:8080")?
            .set_default("upstream.timeout_seconds", 30)?
            // Add support for config file if we want later
            .add_source(File::with_name("config").required(false))
            .add_source(config::Environment::with_prefix("WAF"));

        builder.build()?.try_deserialize()
    }
}
