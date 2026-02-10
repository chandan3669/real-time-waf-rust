use actix_web::{test, web, App};
use waf_rust::waf::inspector::Inspector;
use waf_rust::waf::middleware::WafMiddleware;

#[actix_web::test]
async fn test_normal_request_allowed() {
    let engine = Inspector::new();
    
    let app = test::init_service(
        App::new()
            .wrap(WafMiddleware)
            .app_data(web::Data::new(engine))
            .route("/", web::get().to(|| async { "OK" }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn test_sql_injection_blocked() {
    let engine = Inspector::new();
    
    let app = test::init_service(
        App::new()
            .wrap(WafMiddleware)
            .app_data(web::Data::new(engine))
            .route("/", web::get().to(|| async { "OK" }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/?q=union+select")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn test_xss_blocked() {
    let engine = Inspector::new();
    
    let app = test::init_service(
        App::new()
            .wrap(WafMiddleware)
            .app_data(web::Data::new(engine))
            .route("/", web::get().to(|| async { "OK" }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn test_path_traversal_blocked() {
    let engine = Inspector::new();
    
    let app = test::init_service(
        App::new()
            .wrap(WafMiddleware)
            .app_data(web::Data::new(engine))
            .route("/file", web::get().to(|| async { "OK" }))
    ).await;

    let req = test::TestRequest::get()
        .uri("/file?path=../../etc/passwd")
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}
