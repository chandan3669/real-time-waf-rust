use actix_web::{web, App, HttpServer};
use log::info;
use std::io;

mod server;

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize logging
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    info!("🚀 Starting Simplified Capture Server on http://127.0.0.1:5000");
    info!("📋 Capturing ALL routes and HTTP methods");

    // Start HTTP server
    HttpServer::new(|| {
        App::new()
            // Register our catch-all route handler, which captures requests
            // .default_service() matches ANY path and ANY HTTP method
            .default_service(web::to(server::handle_request))
    })
    .bind(("127.0.0.1", 5000))?  // Listen on port 5000 as requested
    .run()
    .await
}
