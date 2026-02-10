use actix_web::{web, App, HttpServer, middleware::Logger};
use log::info;
use std::io;

use waf_rust::{config, proxy, waf};

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    // Load configuration
    let config = config::WafConfig::load().expect("Failed to load configuration");
    info!("Starting WAF on {}:{}", config.server.host, config.server.port);
    info!("Forwarding to upstream: {}", config.upstream.url);

    let server_config = config.server.clone();
    
    // Create a shared HTTP client for the proxy
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.upstream.timeout_seconds))
        .build()
        .expect("Failed to create HTTP client");

    // Initialize WAF Inspector
    let inspector = waf::inspector::Inspector::new();

    // Prepare shared application data
    let config_data = web::Data::new(config.clone());
    let client_data = web::Data::new(client.clone());
    let inspector_data = web::Data::new(inspector);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(waf::middleware::WafMiddleware) 
            .app_data(client_data.clone())
            .app_data(config_data.clone())
            .app_data(inspector_data.clone())
            .default_service(web::to(proxy::forward_request))
    })
    .bind((server_config.host, server_config.port))?
    .run()
    .await
}
