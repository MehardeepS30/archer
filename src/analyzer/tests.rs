//! Analyzer tests.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use syn::{ExprMethodCall, visit::Visit};

use super::{drift::*, evidence::*, handlers::*, model::*, routes::*, *};

fn route(method: &str, path: &str, scope_prefix: &str, authorization: &str) -> Route {
    let authorization = if authorization == "PRESENT" {
        vec![AuthEvidence {
            kind: AuthEvidenceKind::RoleCheck,
            mechanism: "test_authorization".into(),
            symbol: Some("test_authorization".into()),
            file: PathBuf::from("fixture.rs"),
            line: 1,
            handler: None,
            strength: AuthStrength::Strong,
            requirements: Vec::new(),
        }]
    } else {
        Vec::new()
    };
    Route {
        method: method.into(),
        path: path.into(),
        scope_prefix: scope_prefix.into(),
        handler: None,
        handler_path: None,
        handler_resolution: None,
        authorization,
        line: 1,
        file: PathBuf::from("fixture.rs"),
        unverified: Vec::new(),
        requirement: Requirement::default(),
        resource_keys: Vec::new(),
        caller_use: Vec::new(),
        origin: RouteOrigin::default(),
    }
}

fn route_with_handler(
    method: &str,
    path: &str,
    scope_prefix: &str,
    handler: &str,
    authorization: &str,
) -> Route {
    let mut route = route(method, path, scope_prefix, authorization);
    route.handler = Some(handler.into());
    route
}

#[test]
fn peer_groups_share_a_resource_and_a_method_class() {
    let list = route("GET", "/admin/users", "/admin", "NONE");
    let item = route("GET", "/admin/users/{id}", "/admin", "PRESENT");
    let roles = route("GET", "/admin/users/{id}/roles", "/admin", "PRESENT");
    let delete = route("DELETE", "/admin/users/{id}", "/admin", "PRESENT");
    let other_resource = route("GET", "/admin/orders", "/admin", "PRESENT");
    let other_scope = route("GET", "/public/users", "/public", "PRESENT");

    // Path shape no longer separates a resource's routes.
    assert!(same_peer_group(&list, &item));
    assert!(same_peer_group(&list, &roles));
    // Reads and writes are compared separately.
    assert!(!same_peer_group(&item, &delete));
    assert!(!same_peer_group(&list, &other_resource));
    assert!(!same_peer_group(&list, &other_scope));
    assert_eq!(peer_prefix(&roles), "/admin/users");
}

#[test]
fn authentication_login_and_logout_are_not_peers() {
    let login = route("POST", "/api/auth/login", "/api/auth", "NONE");
    let logout = route("POST", "/api/auth/logout", "/api/auth", "PRESENT");

    assert!(is_authentication_route(&login));
    assert!(is_authentication_route(&logout));
    assert!(!same_peer_group(&login, &logout));
}

#[test]
fn authentication_register_and_logout_are_not_peers() {
    let register = route("POST", "/api/auth/register", "/api/auth", "NONE");
    let logout = route("POST", "/api/auth/logout", "/api/auth", "PRESENT");

    assert!(!same_peer_group(&register, &logout));
}

#[test]
fn single_route_resources_are_compared_across_their_namespace() {
    let users = route("GET", "/api/admin/users", "/api/admin", "PRESENT");
    let orders = route("GET", "/api/admin/orders", "/api/admin", "PRESENT");
    let payments = route("GET", "/api/admin/payments", "/api/admin", "NONE");

    assert!(!same_peer_group(&users, &orders));
    let (groups, _, details, _) = build_analysis_layers(&[users, orders, payments]);
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].level, GroupLevel::Namespace);
    assert_eq!(groups[0].prefix, "/api/admin");
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].suspicious_route.path, "/api/admin/payments");
}

#[test]
fn public_routes_under_broad_api_prefix_are_not_flagged() {
    let routes = vec![
        route("POST", "/api/auth/login", "/api/auth", "NONE"),
        route("POST", "/api/auth/register", "/api/auth", "NONE"),
        route("POST", "/api/auth/logout", "/api/auth", "PRESENT"),
    ];

    let findings = infer_prototype_drift(&routes);

    assert!(findings.is_empty());
}

#[test]
fn duplicate_route_observations_do_not_dominate_peer_inference() {
    let public = route_with_handler("GET", "/api/admin/public", "/api/admin", "public", "NONE");
    let protected = route_with_handler("GET", "/api/admin/users", "/api/admin", "users", "PRESENT");
    let duplicate_protected = protected.clone();

    let protected_orders = route_with_handler(
        "GET",
        "/api/admin/orders",
        "/api/admin",
        "orders",
        "PRESENT",
    );
    let findings =
        infer_prototype_drift(&[public, protected, protected_orders, duplicate_protected]);

    assert_eq!(findings.len(), 1);
    assert!(findings[0].contains("/api/admin/public"));
    assert_eq!(findings[0].matches("/api/admin/users").count(), 1);
}

#[test]
fn analysis_layers_expose_group_invariant_and_finding_relationship() {
    let routes = vec![
        route("GET", "/admin/users", "/admin", "PRESENT"),
        route("GET", "/admin/orders", "/admin", "PRESENT"),
        route("GET", "/admin/reports", "/admin", "PRESENT"),
        route("GET", "/admin/payments", "/admin", "NONE"),
    ];

    let (groups, invariants, details, findings) = build_analysis_layers(&routes);

    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].routes.len(), 4);
    assert_eq!(invariants.len(), 1);
    assert_eq!(invariants[0].peer_group_id, groups[0].id);
    assert_eq!(invariants[0].total_routes, 4);
    assert_eq!(invariants[0].routes_with_authorization, 3);
    assert_eq!(invariants[0].routes_without_authorization, 1);
    assert_eq!(invariants[0].evidence_patterns, vec!["test_authorization"]);
    assert_eq!(invariants[0].strength, AuthStrength::Strong);
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].peer_group_id, groups[0].id);
    assert_eq!(details[0].invariant.routes_without_authorization, 1);
    assert_eq!(details[0].suspicious_route.path, "/admin/payments");
    assert_eq!(findings.len(), 1);
}

#[test]
fn authentication_routes_do_not_create_report_layers() {
    let routes = vec![
        route("POST", "/api/auth/login", "/api/auth", "NONE"),
        route("POST", "/api/auth/register", "/api/auth", "NONE"),
        route("POST", "/api/auth/logout", "/api/auth", "PRESENT"),
    ];

    let (groups, invariants, details, findings) = build_analysis_layers(&routes);

    assert!(groups.is_empty());
    assert!(invariants.is_empty());
    assert!(details.is_empty());
    assert!(findings.is_empty());
}

#[test]
fn lone_writes_are_held_to_privileged_reads_but_not_to_authenticated_ones() {
    let mut routes = vec![
        route("GET", "/admin/payments", "/admin", "NONE"),
        route("GET", "/admin/users", "/admin", "PRESENT"),
        route("GET", "/admin/orders", "/admin", "PRESENT"),
        route("GET", "/admin/reports", "/admin", "PRESENT"),
        route("POST", "/admin/audit", "/admin", "NONE"),
    ];
    let identity = |method: &str, path: &str| {
        let mut route = route(method, path, "/api", "PRESENT");
        route.authorization[0].kind = AuthEvidenceKind::IdentityExtraction;
        route
    };
    routes.extend([
        identity("GET", "/api/orders"),
        identity("GET", "/api/invoices"),
        identity("GET", "/api/profile"),
        route("POST", "/api/webhooks", "/api", "NONE"),
    ]);

    let details = build_analysis_layers(&routes).2;
    let mut reported: Vec<_> = details
        .iter()
        .map(|detail| detail.suspicious_route.path.as_str())
        .collect();
    reported.sort();
    assert_eq!(reported, ["/admin/audit", "/admin/payments"]);
}

#[test]
fn nested_scopes_keep_combined_prefix() {
    let syntax: syn::File = syn::parse_str(
        "fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope(\"/api\").service(
                web::scope(\"/admin\").route(\"/users\", web::get())
            ));
        }",
    )
    .unwrap();
    let index = HandlerIndex::default();
    let mut visitor = RouteVisitor::new(PathBuf::from("nested.rs"), &index);
    visitor.visit_file(&syntax);

    assert_eq!(visitor.routes[0].path, "/api/admin/users");
    assert_eq!(visitor.routes[0].scope_prefix, "/api/admin");
}

#[test]
fn sibling_nested_scopes_extract_routes_and_preserve_admin_drift_evidence() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn admin_users() { require_admin(); }
        async fn admin_orders() { require_admin(); }
        async fn admin_reports() { require_admin(); }
        async fn admin_payments() {}
        async fn admin_audit() { require_admin(); }
        async fn manager_audit() {}
        async fn manager_exports() {}
        async fn finance_summary() {}
        async fn finance_transactions() {}
        async fn get_document() {}
        async fn get_document_history() {}
        async fn health() {}
        async fn readiness() {}

        #[get("/api/profile")]
        async fn profile() {}
        #[get("/api/public-info")]
        async fn public_info() {}
        #[post("/api/session")]
        async fn create_session() {}

        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(
                web::scope("/api")
                    .service(web::scope("/admin")
                        .route("/users", web::get().to(admin_users))
                        .route("/orders", web::get().to(admin_orders))
                        .route("/reports", web::get().to(admin_reports))
                        .route("/payments", web::get().to(admin_payments))
                        .route("/audit", web::post().to(admin_audit)))
                    .service(web::scope("/manager")
                        .route("/audit", web::get().to(manager_audit))
                        .route("/exports", web::get().to(manager_exports)))
                    .service(web::scope("/finance")
                        .route("/summary", web::get().to(finance_summary))
                        .route("/transactions", web::get().to(finance_transactions)))
                    .service(web::scope("/documents")
                        .route("/{id}", web::get().to(get_document))
                        .route("/{id}/history", web::get().to(get_document_history)))
                    .service(web::scope("/public")
                        .route("/health", web::get().to(health))
                        .route("/ready", web::get().to(readiness)))
            );
        }
        "#,
    )
    .unwrap();
    let file = Path::new("siblings.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);

    assert_eq!(visitor.routes.len(), 16);
    for (method, path) in [
        ("GET", "/api/admin/users"),
        ("GET", "/api/admin/orders"),
        ("GET", "/api/admin/reports"),
        ("GET", "/api/admin/payments"),
        ("POST", "/api/admin/audit"),
        ("GET", "/api/manager/audit"),
        ("GET", "/api/manager/exports"),
        ("GET", "/api/finance/summary"),
        ("GET", "/api/finance/transactions"),
        ("GET", "/api/documents/{id}"),
        ("GET", "/api/documents/{id}/history"),
        ("GET", "/api/public/health"),
        ("GET", "/api/public/ready"),
        ("GET", "/api/profile"),
        ("GET", "/api/public-info"),
        ("POST", "/api/session"),
    ] {
        assert!(
            visitor
                .routes
                .iter()
                .any(|route| route.method == method && route.path == path),
            "missing {method} {path}"
        );
    }

    for route in &visitor.routes {
        let expected_scope = ["admin", "manager", "finance", "documents", "public"]
            .iter()
            .find(|scope| route.path.starts_with(&format!("/api/{scope}/")))
            .map(|scope| format!("/api/{scope}"))
            .unwrap_or_default();
        assert_eq!(
            route.scope_prefix, expected_scope,
            "wrong scope for {} {}",
            route.method, route.path
        );
    }

    for handler in ["admin_users", "admin_orders", "admin_reports"] {
        let route = visitor
            .routes
            .iter()
            .find(|route| route.handler.as_deref() == Some(handler))
            .unwrap();
        assert_eq!(route.authorization.len(), 1);
        assert_eq!(route.authorization[0].mechanism, "require_admin");
        assert_eq!(route.authorization[0].handler.as_deref(), Some(handler));
    }
    let audit = visitor
        .routes
        .iter()
        .find(|route| route.path == "/api/admin/audit")
        .unwrap();
    assert_eq!(audit.method, "POST");

    let (groups, invariants, details, findings) = build_analysis_layers(&visitor.routes);
    let admin_group = groups
        .iter()
        .find(|group| {
            group
                .routes
                .iter()
                .any(|route| route.path == "/api/admin/payments")
        })
        .unwrap();
    assert_eq!(admin_group.routes.len(), 4);
    assert!(admin_group.routes.iter().all(|route| route.method == "GET"));
    // Unprotected groups are formed too; the admin group's invariant is
    // the one with protection.
    let invariant = invariants
        .iter()
        .find(|invariant| invariant.peer_group_id == admin_group.id)
        .unwrap();
    assert_eq!(invariants.len(), groups.len());
    assert_eq!(invariant.total_routes, 4);
    assert_eq!(invariant.routes_with_authorization, 3);
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].suspicious_route.path, "/api/admin/payments");
    assert_eq!(details[0].authorized_peer_routes.len(), 3);
    assert_eq!(findings.len(), 1);
}

#[test]
fn resource_routes_take_their_path_from_the_resource() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn users() { require_admin(); }
        async fn orders() { require_admin(); }
        async fn payments() {}
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .service(web::resource("/users").route(web::get().to(users)))
                .service(web::resource("/orders").wrap(AdminMiddleware).route(web::get().to(orders)))
                .service(web::resource("/payments").route(web::get().to(payments)).route(web::post().to(h))));
            cfg.service(web::resource("/health").route(web::get().to(h)));
            cfg.route("/plain", web::get().to(h));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("resources.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let mut found: Vec<(&str, &str, &str)> = visitor
        .routes
        .iter()
        .map(|route| {
            (
                route.method.as_str(),
                route.path.as_str(),
                route.scope_prefix.as_str(),
            )
        })
        .collect();
    found.sort();

    assert_eq!(
        found,
        vec![
            ("GET", "/admin/orders", "/admin"),
            ("GET", "/admin/payments", "/admin"),
            ("GET", "/admin/users", "/admin"),
            ("GET", "/health", "/"),
            ("GET", "/plain", "/"),
            ("POST", "/admin/payments", "/admin"),
        ]
    );
    let orders = visitor
        .routes
        .iter()
        .find(|route| route.path == "/admin/orders")
        .unwrap();
    let kinds: Vec<_> = orders
        .authorization
        .iter()
        .map(|e| e.kind.clone())
        .collect();
    assert_eq!(
        kinds,
        vec![
            AuthEvidenceKind::AuthorizationMiddleware,
            AuthEvidenceKind::RoleCheck
        ]
    );
    let users = visitor
        .routes
        .iter()
        .find(|route| route.path == "/admin/users")
        .unwrap();
    assert_eq!(users.line, 9);

    // Both methods of the unprotected resource fall short: the read of its
    // namespace peers, the write of the privilege the namespace's reads need.
    let (_, _, details, _) = build_analysis_layers(&visitor.routes);
    let mut reported: Vec<_> = details
        .iter()
        .map(|detail| {
            (
                detail.suspicious_route.method.as_str(),
                detail.suspicious_route.path.as_str(),
            )
        })
        .collect();
    reported.sort();
    assert_eq!(
        reported,
        [("GET", "/admin/payments"), ("POST", "/admin/payments")]
    );
}

#[test]
fn malformed_rust_file_is_reported_and_skipped() {
    let root = std::env::temp_dir().join(format!("archer-malformed-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("broken.rs"), "fn broken( {").unwrap();
    fs::write(
        root.join("valid.rs"),
        "fn configure(cfg: &mut web::ServiceConfig) { cfg.service(web::scope(\"/admin\").route(\"/users\", web::get())); }",
    )
    .unwrap();

    let report = analyze_repository(&root).unwrap();
    fs::remove_dir_all(&root).unwrap();

    assert_eq!(report.files_scanned, 2);
    assert_eq!(report.parse_errors.len(), 1);
    assert!(report.parse_errors[0].contains("broken.rs"));
    assert_eq!(report.routes.len(), 1);
}

#[test]
fn recognizes_authorization_guards_and_middleware_but_not_generic_guards() {
    let guard: ExprMethodCall =
        syn::parse_str("web::scope(\"/admin\").route(\"/x\", web::get().guard(AdminGuard))")
            .unwrap();
    let middleware: ExprMethodCall = syn::parse_str(
        "web::scope(\"/admin\").route(\"/x\", web::get().wrap(AuthorizationMiddleware))",
    )
    .unwrap();
    let generic_guard: ExprMethodCall =
        syn::parse_str("web::scope(\"/admin\").route(\"/x\", web::get().guard(MethodGuard))")
            .unwrap();

    let guard_evidence = classify_authorization(&guard, None, &[], Path::new("fixture.rs"));
    assert_eq!(guard_evidence[0].kind, AuthEvidenceKind::AuthorizationGuard);
    assert_eq!(guard_evidence[0].symbol.as_deref(), Some("AdminGuard"));
    assert_eq!(guard_evidence[0].line, 1);
    assert_eq!(guard_evidence[0].strength, AuthStrength::Strong);

    let middleware_evidence =
        classify_authorization(&middleware, None, &[], Path::new("fixture.rs"));
    assert_eq!(
        middleware_evidence[0].kind,
        AuthEvidenceKind::AuthorizationMiddleware
    );
    assert_eq!(
        middleware_evidence[0].symbol.as_deref(),
        Some("AuthorizationMiddleware")
    );
    assert_eq!(middleware_evidence[0].line, 1);

    let generic_evidence =
        classify_authorization(&generic_guard, None, &[], Path::new("fixture.rs"));
    assert!(generic_evidence.is_empty());
}

#[test]
fn http_method_extraction_follows_the_route_builder_chain() {
    // Fixtures are route registrations parsed with `syn`. Constructors and
    // method constants follow actix-web 4: `web::{get, post, put, patch,
    // delete, head, trace}`, `web::method(Method::X)`, `web::route()`, and
    // `Route::method(Method::X)`, which adds a method guard. OPTIONS and
    // CONNECT have no `web::` constructor and are written with `Method::`.
    for (route, expected) in [
        // Cases from the reviewed branch commit 05561a3.
        (
            r#"web::scope("/api").route("/users", web::get().to(h))"#,
            "GET",
        ),
        (
            r#"web::scope("/api").route("/users", web::post().guard(AdminGuard).to(h))"#,
            "POST",
        ),
        (r#"web::scope("/api").route("/users", get().to(h))"#, "GET"),
        (
            r#"web::scope("/api").route("/users", actix_web::web::delete().to(h))"#,
            "DELETE",
        ),
        (r#"web::resource("/users").route(web::put().to(h))"#, "PUT"),
        (
            r#"web::scope("/api").route("/web/get_users", custom_helper("web::get"))"#,
            "UNKNOWN",
        ),
        // Calls nested in guard, configuration, or handler arguments are ignored.
        (
            r#"cfg.route("/mode", web::route().guard(guard::Header("x-mode", config.get("mode"))).to(h))"#,
            "UNKNOWN",
        ),
        (
            r#"cfg.route("/flag", web::post().guard(guard::fn_guard(|ctx| config.get("flag").is_some())).to(h))"#,
            "POST",
        ),
        (
            r#"cfg.route("/users", web::post().to(web::get_users))"#,
            "POST",
        ),
        (r#"cfg.route("/users", my_routes::get().to(h))"#, "UNKNOWN"),
        // Remaining constructors.
        (r#"cfg.route("/x", web::patch().to(h))"#, "PATCH"),
        (r#"cfg.route("/x", web::head().to(h))"#, "HEAD"),
        (r#"cfg.route("/x", web::trace().to(h))"#, "TRACE"),
        (r#"cfg.route("/x", web::options().to(h))"#, "UNKNOWN"),
        // `web::method(...)` with qualified constants.
        (r#"cfg.route("/x", web::method(Method::PUT).to(h))"#, "PUT"),
        (
            r#"cfg.route("/x", web::method(http::Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", actix_web::web::method(actix_web::http::Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", web::method(Method::OPTIONS).to(h))"#,
            "OPTIONS",
        ),
        (
            r#"cfg.route("/x", web::method(Method::from_bytes(b"PUT").unwrap()).to(h))"#,
            "UNKNOWN",
        ),
        // `Route::method(...)` on an any-method route.
        (
            r#"cfg.route("/x", web::route().method(Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", web::route().method(http::Method::CONNECT).guard(g).to(h))"#,
            "CONNECT",
        ),
        (
            r#"cfg.route("/x", Route::new().method(Method::DELETE).to(h))"#,
            "DELETE",
        ),
        (r#"cfg.route("/x", web::route().to(h))"#, "UNKNOWN"),
        // Method guards that agree keep the method; conflicting ones do not.
        (
            r#"cfg.route("/x", web::get().method(Method::GET).to(h))"#,
            "GET",
        ),
        (
            r#"cfg.route("/x", web::get().method(Method::POST).to(h))"#,
            "UNKNOWN",
        ),
    ] {
        let call: ExprMethodCall = syn::parse_str(route).unwrap();
        assert_eq!(extract_http_method(&call), expected, "{route}");
    }
}

#[test]
fn extracted_routes_carry_builder_methods_without_changing_handler_resolution() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn get_users() { require_admin(); }
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/api")
                .route("/users", web::post().to(get_users))
                .route("/mode", web::route().guard(guard::Header("x-mode", config.get("mode"))).to(h))
                .route("/web/get_users", custom_helper("web::get"))
                .route("/put", web::route().method(Method::PUT).to(h)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("methods.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let route = |path: &str| {
        visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    };

    assert_eq!(visitor.routes.len(), 4);
    assert_eq!(route("/api/users").method, "POST");
    assert_eq!(route("/api/mode").method, "UNKNOWN");
    assert_eq!(route("/api/web/get_users").method, "UNKNOWN");
    assert_eq!(route("/api/put").method, "PUT");

    let users = route("/api/users");
    assert_eq!(users.handler_resolution, Some(HandlerResolution::Local));
    assert_eq!(users.authorization.len(), 1);
    assert_eq!(users.authorization[0].mechanism, "require_admin");
}

#[test]
fn extracts_attribute_routes_and_associates_handlers() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}

        #[get("/admin")]
        fn admin() {
            require_admin();
        }

        #[post("/token")]
        fn token() {}
        "#,
    )
    .unwrap();
    let index = HandlerIndex::single_file(Path::new("attributes.rs"), &syntax);
    let mut visitor = RouteVisitor::new(PathBuf::from("attributes.rs"), &index);
    visitor.visit_file(&syntax);

    assert_eq!(visitor.routes.len(), 2);
    assert_eq!(visitor.routes[0].method, "GET");
    assert_eq!(visitor.routes[0].path, "/admin");
    assert!(visitor.routes[0].is_authorized());
    assert_eq!(visitor.routes[0].handler.as_deref(), Some("admin"));
    assert_eq!(
        visitor.routes[0].authorization[0].kind,
        AuthEvidenceKind::RoleCheck
    );
    assert_eq!(
        visitor.routes[0].authorization[0].symbol.as_deref(),
        Some("require_admin")
    );
    assert_eq!(visitor.routes[0].authorization[0].line, 6);
    assert_eq!(visitor.routes[1].method, "POST");
    assert_eq!(visitor.routes[1].path, "/token");
    assert!(!visitor.routes[1].is_authorized());
}

#[test]
fn role_check_records_symbol_line_and_handler() {
    let syntax: syn::File = syn::parse_str("fn admin() { require_admin(); }").unwrap();
    let handlers = collect_authorized_handlers(Path::new("roles.rs"), &syntax);
    let evidence = &handlers["admin"][0];

    assert_eq!(evidence.kind, AuthEvidenceKind::RoleCheck);
    assert_eq!(evidence.mechanism, "require_admin");
    assert_eq!(evidence.symbol.as_deref(), Some("require_admin"));
    assert_eq!(evidence.file, PathBuf::from("roles.rs"));
    assert_eq!(evidence.line, 1);
    assert_eq!(evidence.handler.as_deref(), Some("admin"));
    assert_eq!(evidence.strength, AuthStrength::Strong);
}

#[test]
fn function_call_evidence_recognizes_checks_without_promoting_identity_or_names() {
    let syntax: syn::File = syn::parse_str(
        "fn protected() {
            check_permission();
            verify_finance_permission();
            require_manager();
            check_resource_owner();
            require_authenticated_user();
            admin_dashboard_title();
            let _ = AuthError::Unauthorized;
        }",
    )
    .unwrap();
    let handlers = collect_authorized_handlers(Path::new("calls.rs"), &syntax);
    let evidence = &handlers["protected"];

    assert_eq!(evidence.len(), 5);
    assert_eq!(evidence[0].kind, AuthEvidenceKind::PermissionCheck);
    assert_eq!(evidence[0].mechanism, "check_permission");
    assert_eq!(evidence[0].symbol.as_deref(), Some("check_permission"));
    assert_eq!(evidence[1].kind, AuthEvidenceKind::PermissionCheck);
    assert_eq!(evidence[1].mechanism, "verify_finance_permission");
    assert_eq!(evidence[2].kind, AuthEvidenceKind::RoleCheck);
    assert_eq!(evidence[2].mechanism, "require_manager");
    assert_eq!(evidence[3].kind, AuthEvidenceKind::OwnershipCheck);
    assert_eq!(evidence[3].mechanism, "check_resource_owner");
    assert_eq!(evidence[4].kind, AuthEvidenceKind::IdentityExtraction);
    assert_eq!(evidence[4].mechanism, "require_authenticated_user");
    assert!(
        evidence
            .iter()
            .all(|item| item.handler.as_deref() == Some("protected"))
    );
    assert!(
        !evidence
            .iter()
            .any(|item| item.mechanism == "admin_dashboard_title")
    );
    assert!(
        !evidence.iter().any(
            |item| item.kind == AuthEvidenceKind::IdentityExtraction && item.is_authorization()
        )
    );

    let error_syntax: syn::File = syn::parse_str(
        "fn error_only() -> Result<(), AuthError> { Err(AuthError::Forbidden) }
         fn matches_error(error: AuthError) { match error { AuthError::Forbidden => (), _ => () } }",
    )
    .unwrap();
    let error_handlers = collect_authorized_handlers(Path::new("errors.rs"), &error_syntax);
    assert!(!error_handlers.contains_key("error_only"));
    assert!(!error_handlers.contains_key("matches_error"));
}

#[test]
fn access_token_and_access_log_helpers_are_not_authorization() {
    let syntax: syn::File = syn::parse_str(
        "fn token_only() { verify_access_token(); }
         fn log_only() { check_access_log(); }
         fn permission() { check_permission(); }
         fn access() { check_access(); }
         fn resource_access() { verify_resource_access(); }",
    )
    .unwrap();
    let handlers = collect_authorized_handlers(Path::new("access.rs"), &syntax);

    assert!(!handlers.contains_key("token_only"));
    assert!(!handlers.contains_key("log_only"));
    for (handler, mechanism) in [
        ("permission", "check_permission"),
        ("access", "check_access"),
        ("resource_access", "verify_resource_access"),
    ] {
        let evidence = &handlers[handler];
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, AuthEvidenceKind::PermissionCheck);
        assert_eq!(evidence[0].mechanism, mechanism);
        assert_eq!(evidence[0].strength, AuthStrength::Strong);
    }

    let token_route = Route {
        method: "GET".into(),
        path: "/token-only".into(),
        scope_prefix: String::new(),
        handler: Some("token_only".into()),
        handler_path: None,
        handler_resolution: None,
        authorization: handlers.get("token_only").cloned().unwrap_or_default(),
        line: 1,
        file: PathBuf::from("access.rs"),
        unverified: Vec::new(),
        requirement: Requirement::default(),
        resource_keys: Vec::new(),
        caller_use: Vec::new(),
        origin: RouteOrigin::default(),
    };
    assert!(!token_route.is_authorized());
}

#[test]
fn helper_names_separate_enforcement_from_lookups_and_authentication() {
    use AuthEvidenceKind::*;
    for (name, expected) in [
        // Plausible enforcement helpers.
        ("require_admin", Some(RoleCheck)),
        ("has_role", Some(RoleCheck)),
        ("check_roles", Some(RoleCheck)),
        ("is_admin", Some(RoleCheck)),
        ("check_permission", Some(PermissionCheck)),
        ("verify_finance_permission", Some(PermissionCheck)),
        ("verify_resource_access", Some(PermissionCheck)),
        ("check_resource_owner", Some(OwnershipCheck)),
        ("is_owned_by", Some(OwnershipCheck)),
        ("authorize", Some(ManualAuthorizationCheck)),
        ("authorize_request", Some(ManualAuthorizationCheck)),
        // Authentication is identity, never authorization.
        ("require_auth", Some(IdentityExtraction)),
        ("require_authenticated_user", Some(IdentityExtraction)),
        // Misleading names: token validation, lookups, logging, and data.
        ("verify_access_token", None),
        ("check_username", None),
        ("ensure_user_exists", None),
        ("verify_oauth_state", None),
        ("check_access_log", None),
        ("ensure_admin_exists", None),
        ("check_admin_token", None),
        ("role_name", None),
        ("permissions_list", None),
        ("authorized_user", None),
        ("downstream", None),
        ("author_name", None),
        ("handle_auth_error", None),
    ] {
        assert_eq!(
            classify_check_name(name).map(|(kind, _)| kind),
            expected,
            "{name}"
        );
    }
}

#[test]
fn method_calls_use_word_rules_instead_of_substrings() {
    let syntax: syn::File = syn::parse_str(
        "fn is_admin_method(user: User) { if !user.is_admin() { return; } }
         fn has_role_method(user: User) { if !user.has_role(\"admin\") { return; } }
         fn owns_method(user: User) { if !user.owns(&doc) { return; } }
         fn authorize_method(policy: Policy) { policy.authorize(&user); }
         fn claims_method(req: Req) { req.extract_claims(); }
         fn misleading_methods(user: User, stream: Stream, req: Req) {
             user.role_name();
             user.permissions_list();
             req.authorized_user();
             stream.downstream();
         }",
    )
    .unwrap();
    let handlers = collect_authorized_handlers(Path::new("methods.rs"), &syntax);

    for (handler, kind) in [
        ("is_admin_method", AuthEvidenceKind::RoleCheck),
        ("has_role_method", AuthEvidenceKind::RoleCheck),
        ("owns_method", AuthEvidenceKind::OwnershipCheck),
        (
            "authorize_method",
            AuthEvidenceKind::ManualAuthorizationCheck,
        ),
        ("claims_method", AuthEvidenceKind::IdentityExtraction),
    ] {
        let evidence = &handlers[handler];
        assert_eq!(evidence.len(), 1, "{handler}");
        assert_eq!(evidence[0].kind, kind, "{handler}");
    }
    assert!(!handlers["claims_method"][0].is_authorization());
    assert!(!handlers.contains_key("misleading_methods"));
}

#[test]
fn route_configuration_names_separate_authorization_from_authentication() {
    assert_eq!(
        camel_case_words("AdminAuthMiddleware"),
        ["admin", "auth", "middleware"]
    );
    assert_eq!(camel_case_words("JWTGuard"), ["jwt", "guard"]);
    assert_eq!(
        camel_case_words("HttpAuthentication"),
        ["http", "authentication"]
    );

    let evidence = |route: &str| {
        let call: ExprMethodCall = syn::parse_str(route).unwrap();
        classify_authorization(&call, None, &[], Path::new("fixture.rs"))
            .into_iter()
            .map(|item| (item.kind, item.mechanism, item.strength))
            .collect::<Vec<_>>()
    };
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    for (route, expected) in [
        (
            r#"web::scope("/a").route("/x", web::get().guard(AdminGuard).to(h))"#,
            vec![(AuthorizationGuard, "AdminGuard", Strong)],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(guard::fn_guard(check_admin)).to(h))"#,
            vec![(AuthorizationGuard, "check_admin", Strong)],
        ),
        (
            r#"web::scope("/a").wrap(RequireAdmin).route("/x", web::get().to(h))"#,
            vec![(AuthorizationMiddleware, "RequireAdmin", Medium)],
        ),
        (
            r#"web::scope("/a").wrap(AdminAuthMiddleware).route("/x", web::get().to(h))"#,
            vec![(AuthorizationMiddleware, "AdminAuthMiddleware", Medium)],
        ),
        (
            r#"web::scope("/a").wrap(AuthMiddleware).route("/x", web::get().to(h))"#,
            vec![(IdentityExtraction, "AuthMiddleware", Weak)],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(AuthGuard).to(h))"#,
            vec![(IdentityExtraction, "AuthGuard", Weak)],
        ),
        (
            r#"web::scope("/a").wrap(HttpAuthentication::bearer(validator)).route("/x", web::get().to(h))"#,
            vec![(IdentityExtraction, "HttpAuthentication", Weak)],
        ),
        (
            r#"web::scope("/a").wrap(UnauthorizedHandler).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(PermissionsPolicy::default()).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(RoleLogger).route("/x", web::get().to(h))"#,
            vec![],
        ),
        // Authorization and guard words, but an error-mapping or logging type.
        (
            r#"web::scope("/a").wrap(AuthorizationErrorMiddleware).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(RoleCheckLogger).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(guard::Header("x-role", "admin")).to(h))"#,
            vec![],
        ),
    ] {
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(kind, mechanism, strength)| (kind, mechanism.to_owned(), strength))
            .collect();
        assert_eq!(evidence(route), expected, "{route}");
    }
}

#[test]
fn guard_and_middleware_evidence_keeps_handler_evidence() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn guarded() { check_permission(); }
        async fn authenticated_admin() { require_admin(); }
        async fn authenticated_only() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.route("/guarded", web::get().guard(AdminGuard).to(guarded));
            cfg.service(web::scope("/session")
                .wrap(AuthMiddleware)
                .route("/admin", web::get().to(authenticated_admin)));
            cfg.service(web::scope("/session")
                .wrap(AuthMiddleware)
                .route("/plain", web::get().to(authenticated_only)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("mixed.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let kinds = |path: &str| {
        let route = visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap();
        (
            route.is_authorized(),
            route
                .authorization
                .iter()
                .map(|item| item.kind.clone())
                .collect::<Vec<_>>(),
        )
    };
    use AuthEvidenceKind::*;

    assert_eq!(
        kinds("/guarded"),
        (true, vec![AuthorizationGuard, PermissionCheck])
    );
    assert_eq!(
        kinds("/session/admin"),
        (true, vec![IdentityExtraction, RoleCheck])
    );
    assert_eq!(kinds("/session/plain"), (false, vec![IdentityExtraction]));
}

fn route_evidence(source: &str) -> HashMap<String, Vec<(AuthEvidenceKind, String)>> {
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    visitor
        .routes
        .into_iter()
        .map(|route| {
            let evidence = route
                .authorization
                .into_iter()
                .map(|item| (item.kind, item.mechanism))
                .collect();
            (route.path, evidence)
        })
        .collect()
}

#[test]
fn scope_middleware_applies_to_every_route_in_its_chain() {
    // Actix applies a scope's `.wrap(...)` to all of the scope's routes,
    // wherever the call appears in the builder chain.
    let evidence = route_evidence(
        r#"
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/before").wrap(AdminMiddleware)
                .route("/a", web::get().to(h))
                .route("/b", web::get().to(h)));
            cfg.service(web::scope("/between")
                .route("/a", web::get().to(h))
                .wrap(AdminMiddleware)
                .route("/b", web::get().to(h)));
            cfg.service(web::scope("/after")
                .route("/a", web::get().to(h))
                .route("/b", web::get().to(h))
                .wrap(AdminMiddleware));
            cfg.service(web::scope("/leak")
                .route("/a", web::get().guard(AdminGuard).to(h))
                .wrap(Logger::default())
                .route("/b", web::get().to(h)));
        }
        "#,
    );
    let middleware = vec![(
        AuthEvidenceKind::AuthorizationMiddleware,
        "AdminMiddleware".to_owned(),
    )];
    for scope in ["/before", "/between", "/after"] {
        for route in ["a", "b"] {
            let path = format!("{scope}/{route}");
            assert_eq!(evidence[&path], middleware, "{path}");
        }
    }
    // A sibling route's own guard is not scope configuration.
    assert_eq!(
        evidence["/leak/a"],
        vec![(
            AuthEvidenceKind::AuthorizationGuard,
            "AdminGuard".to_owned()
        )]
    );
    assert!(evidence["/leak/b"].is_empty());
}

#[test]
fn nested_scopes_inherit_middleware_without_leaking_to_siblings() {
    let evidence = route_evidence(
        r#"
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/api").wrap(AuthMiddleware)
                .service(web::scope("/admin").wrap(AdminMiddleware)
                    .route("/x", web::get().to(h))
                    .service(web::scope("/deep").guard(RoleGuard)
                        .route("/z", web::get().to(h))))
                .service(web::scope("/public")
                    .route("/y", web::get().to(h)))
                .route("/direct", web::get().to(h)));
            cfg.service(web::scope("/other").route("/w", web::get().to(h)));
        }
        "#,
    );
    use AuthEvidenceKind::*;
    let kinds = |path: &str| {
        let mut found: Vec<(AuthEvidenceKind, &str)> = evidence[path]
            .iter()
            .map(|(kind, mechanism)| (kind.clone(), mechanism.as_str()))
            .collect();
        found.sort_by_key(|(_, mechanism)| mechanism.to_owned());
        found
    };

    assert_eq!(
        kinds("/api/admin/x"),
        vec![
            (AuthorizationMiddleware, "AdminMiddleware"),
            (IdentityExtraction, "AuthMiddleware"),
        ]
    );
    assert_eq!(
        kinds("/api/admin/deep/z"),
        vec![
            (AuthorizationMiddleware, "AdminMiddleware"),
            (IdentityExtraction, "AuthMiddleware"),
            (AuthorizationGuard, "RoleGuard"),
        ]
    );
    // Siblings receive the shared parent's middleware but not each other's.
    assert_eq!(
        kinds("/api/public/y"),
        vec![(IdentityExtraction, "AuthMiddleware")]
    );
    assert_eq!(
        kinds("/api/direct"),
        vec![(IdentityExtraction, "AuthMiddleware")]
    );
    // An unrelated top-level scope receives nothing.
    assert!(evidence["/other/w"].is_empty());
}

#[test]
fn scope_middleware_is_kept_alongside_handler_evidence() {
    let source = r#"
        fn require_admin() {}
        async fn users() { require_admin(); }
        async fn orders() { require_admin(); }
        async fn payments() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin").wrap(AdminMiddleware)
                .route("/users", web::get().to(users))
                .route("/orders", web::get().to(orders))
                .route("/payments", web::get().to(payments)));
        }
    "#;
    let evidence = route_evidence(source);
    use AuthEvidenceKind::*;
    for path in ["/admin/users", "/admin/orders"] {
        assert_eq!(
            evidence[path],
            vec![
                (AuthorizationMiddleware, "AdminMiddleware".to_owned()),
                (RoleCheck, "require_admin".to_owned()),
            ],
            "{path}"
        );
    }
    assert_eq!(
        evidence["/admin/payments"],
        vec![(AuthorizationMiddleware, "AdminMiddleware".to_owned())]
    );

    // Every route is authorized by the scope middleware, so no drift remains.
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let (_, _, details, _) = build_analysis_layers(&visitor.routes);
    assert!(details.is_empty());
}

#[test]
fn route_and_handler_names_alone_do_not_count_as_protection() {
    let syntax: syn::File = syn::parse_str(
        r#"
        async fn require_admin_panel() {}
        async fn admin_only() {}
        #[get("/admin/attribute")]
        async fn check_permission() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/panel", web::get().to(require_admin_panel))
                .route("/secure", web::get().to(admin_only)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("names.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);

    assert_eq!(visitor.routes.len(), 3);
    for route in &visitor.routes {
        assert!(route.authorization.is_empty(), "{}", route.path);
        assert!(!route.is_authorized(), "{}", route.path);
    }
}

#[test]
fn identity_extraction_is_not_authorization() {
    let syntax: syn::File =
        syn::parse_str("fn profile() { let claims = Claims::from_request(); }").unwrap();
    let handlers = collect_authorized_handlers(Path::new("identity.rs"), &syntax);
    let evidence = &handlers["profile"][0];
    assert_eq!(evidence.kind, AuthEvidenceKind::IdentityExtraction);

    let route = Route {
        method: "GET".into(),
        path: "/profile".into(),
        scope_prefix: String::new(),
        handler: Some("profile".into()),
        handler_path: None,
        handler_resolution: None,
        authorization: handlers["profile"].clone(),
        line: 1,
        file: PathBuf::from("identity.rs"),
        unverified: Vec::new(),
        requirement: Requirement::default(),
        resource_keys: Vec::new(),
        caller_use: Vec::new(),
        origin: RouteOrigin::default(),
    };
    assert!(!route.is_authorized());
    assert!(route.strongest_evidence().is_none());
}

#[test]
fn logger_and_compress_are_not_authorization_middleware() {
    for middleware in ["Logger", "Compress"] {
        let route: ExprMethodCall = syn::parse_str(&format!(
            "web::scope(\"/admin\").route(\"/x\", web::get().wrap({middleware}))"
        ))
        .unwrap();
        assert!(classify_authorization(&route, None, &[], Path::new("fixture.rs")).is_empty());
    }
}

#[test]
fn empty_route_has_no_authorization_evidence() {
    let route = route("GET", "/admin/payments", "/admin", "NONE");
    assert!(route.authorization.is_empty());
    assert!(!route.is_authorized());
    assert_eq!(
        route.evidence_summary(),
        "No recognized authorization evidence"
    );
}

#[test]
fn nested_handlers_resolve_in_their_lexical_block_only() {
    let syntax: syn::File = syn::parse_str(
        "fn require_admin() {}
async fn health() { require_admin(); }
fn configure_admin(cfg: &mut web::ServiceConfig) {
async fn list() { require_admin(); }
cfg.route(\"/admin/list\", web::get().to(list));
cfg.route(\"/admin/late\", web::get().to(late));
async fn late() { require_admin(); }
}
fn configure_public(cfg: &mut web::ServiceConfig) {
async fn list() {}
async fn health() {}
cfg.route(\"/public/list\", web::get().to(list));
cfg.route(\"/public/health\", web::get().to(health));
cfg.route(\"/public/module-health\", web::get().to(self::health));
App::new().route(\"/public/closure\", web::get().to(list));
{
    async fn list() { require_admin(); }
    cfg.route(\"/public/inner-block\", web::get().to(list));
}
}
fn configure_duplicate(cfg: &mut web::ServiceConfig) {
async fn health() {}
async fn health() { require_admin(); }
cfg.route(\"/duplicate/health\", web::get().to(health));
}
fn configure_top(cfg: &mut web::ServiceConfig) {
cfg.route(\"/top/health\", web::get().to(health));
cfg.route(\"/top/late\", web::get().to(late));
}",
    )
    .unwrap();
    let file = Path::new("nested.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let route = |path: &str| {
        visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    };

    // Protected nested handlers, including one declared after its route,
    // and an inner block's `list` shadowing its enclosing block's `list`.
    for (path, line) in [
        ("/admin/list", 4),
        ("/admin/late", 7),
        ("/public/inner-block", 17),
    ] {
        let route = route(path);
        assert_eq!(
            route.handler_resolution,
            Some(HandlerResolution::Local),
            "{path}"
        );
        assert_eq!(route.authorization.len(), 1, "{path}");
        assert_eq!(route.authorization[0].line, line, "{path}");
    }

    // A sibling's nested `list`, and a nested `health` that shadows the
    // protected module-level `health`, lend no evidence; closures inside
    // the block see the block's own `list`.
    for path in ["/public/list", "/public/health", "/public/closure"] {
        assert_eq!(
            route(path).handler_resolution,
            Some(HandlerResolution::Local),
            "{path}"
        );
        assert!(route(path).authorization.is_empty(), "{path}");
    }

    // Qualified paths bypass block scopes and reach the module-level definition.
    let module_health = route("/public/module-health");
    assert_eq!(
        module_health.handler_resolution,
        Some(HandlerResolution::Qualified)
    );
    assert_eq!(module_health.authorization[0].line, 2);

    // A duplicate declaration fails safely instead of borrowing either
    // candidate or the module-level `health`.
    let duplicate = route("/duplicate/health");
    assert_eq!(
        duplicate.handler_resolution,
        Some(HandlerResolution::Unresolved)
    );
    assert!(duplicate.authorization.is_empty());

    // Outside those blocks, `health` is the module-level definition, and
    // another function's nested `late` is not reachable even by fallback.
    let top_health = route("/top/health");
    assert_eq!(
        top_health.handler_resolution,
        Some(HandlerResolution::Local)
    );
    assert_eq!(top_health.authorization[0].line, 2);
    let top_late = route("/top/late");
    assert_eq!(
        top_late.handler_resolution,
        Some(HandlerResolution::Unresolved)
    );
    assert!(top_late.authorization.is_empty());
}

#[test]
fn nested_function_bodies_do_not_lend_evidence_to_the_enclosing_handler() {
    let syntax: syn::File = syn::parse_str(
        "fn require_admin() {}
async fn report() {
fn report_helper() { require_admin(); }
}
async fn audited() {
require_admin();
fn audited_helper() { check_permission(); }
}
async fn with_methods() {
struct Helper;
impl Helper { fn check(&self) { require_admin(); } }
trait Guarded { fn guarded(&self) { require_admin(); } }
}
async fn branchy(flag: bool) {
if flag { let _ = { require_admin(); }; }
let check = || require_admin();
check();
}
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/report\", web::get().to(report))
    .route(\"/audited\", web::get().to(audited))
    .route(\"/with-methods\", web::get().to(with_methods))
    .route(\"/branchy\", web::get().to(branchy));
}",
    )
    .unwrap();
    let file = Path::new("nested-evidence.rs");
    let handlers = collect_authorized_handlers(file, &syntax);

    // An uncalled nested helper, or nested impl/trait methods, lend nothing.
    assert!(!handlers.contains_key("report"));
    assert!(!handlers.contains_key("with_methods"));
    // The nested helper still owns its evidence.
    let helper = &handlers["report_helper"];
    assert_eq!(helper.len(), 1);
    assert_eq!(helper[0].line, 3);
    assert_eq!(helper[0].handler.as_deref(), Some("report_helper"));
    // Positive control: the outer handler's direct call is still recognized,
    // without the nested helper's permission check.
    let audited = &handlers["audited"];
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0].kind, AuthEvidenceKind::RoleCheck);
    assert_eq!(audited[0].mechanism, "require_admin");
    assert_eq!(audited[0].line, 6);
    // Nested blocks, branches, and closures in the handler are still traversed.
    let branchy_lines: Vec<usize> = handlers["branchy"].iter().map(|item| item.line).collect();
    assert_eq!(branchy_lines, vec![15, 16]);

    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let route = |path: &str| {
        visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    };
    for path in ["/report", "/with-methods"] {
        assert!(route(path).authorization.is_empty(), "{path}");
        assert!(!route(path).is_authorized(), "{path}");
    }
    assert_eq!(route("/audited").authorization.len(), 1);
    assert!(route("/audited").is_authorized());
    assert_eq!(route("/branchy").authorization.len(), 2);
}

#[test]
fn inline_modules_do_not_see_enclosing_block_handlers() {
    // `list` is not in scope inside `mod inner` (rustc rejects it); the
    // analyzer must fail safely rather than borrow the block's evidence.
    let syntax: syn::File = syn::parse_str(
        "fn require_admin() {}
fn configure(cfg: &mut web::ServiceConfig) {
async fn list() { require_admin(); }
mod inner {
    fn configure(cfg: &mut web::ServiceConfig) {
        async fn own() { require_admin(); }
        cfg.route(\"/inner/list\", web::get().to(list));
        cfg.route(\"/inner/own\", web::get().to(own));
    }
}
cfg.route(\"/outer/list\", web::get().to(list));
}",
    )
    .unwrap();
    let file = Path::new("inline-module.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let route = |path: &str| {
        visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    };

    let inner_list = route("/inner/list");
    assert_eq!(
        inner_list.handler_resolution,
        Some(HandlerResolution::Unresolved)
    );
    assert!(inner_list.authorization.is_empty());

    // The module's own blocks still resolve, and the enclosing block's
    // scope is restored after the module.
    for (path, line) in [("/inner/own", 6), ("/outer/list", 3)] {
        let route = route(path);
        assert_eq!(
            route.handler_resolution,
            Some(HandlerResolution::Local),
            "{path}"
        );
        assert_eq!(route.authorization.len(), 1, "{path}");
        assert_eq!(route.authorization[0].line, line, "{path}");
    }
}

#[test]
fn local_bindings_shadow_handler_names_in_lexical_order() {
    let source = "fn require_admin() {}
async fn health() { require_admin(); }
async fn public_health() {}
struct Wrapper<T> { inner: T }
struct Routes;
impl Routes {
fn register(cfg: &mut web::ServiceConfig, health: u8) {
    cfg.route(\"/method-param\", web::get().to(health));
}
}
fn register<H>(cfg: &mut web::ServiceConfig, health: H) {
cfg.route(\"/param\", web::get().to(health));
}
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/unshadowed\", web::get().to(health));
{
    let health = || async {};
    cfg.route(\"/closure\", web::get().to(health));
}
{
    let health = public_health;
    cfg.route(\"/variable\", web::get().to(health));
}
{
    cfg.route(\"/before-let\", web::get().to(health));
    let health = {
        cfg.route(\"/own-initializer\", web::get().to(health));
        public_health
    };
    cfg.route(\"/after-let\", web::get().to(health));
    cfg.route(\"/qualified\", web::get().to(self::health));
    cfg.route(\"/crate-qualified\", web::get().to(crate::health));
}
{
    let (health, _) = (public_health, 1);
    cfg.route(\"/destructured\", web::get().to(health));
}
{
    let Wrapper { inner: health } = Wrapper { inner: public_health };
    cfg.route(\"/struct-pattern\", web::get().to(health));
}
for health in [public_health] {
    cfg.route(\"/for\", web::get().to(health));
}
cfg.route(\"/after-for\", web::get().to(health));
match Some(public_health) {
    Some(health) if true => { cfg.route(\"/match\", web::get().to(health)); }
    _ => { cfg.route(\"/other-arm\", web::get().to(health)); }
}
cfg.route(\"/after-match\", web::get().to(health));
if let Some(health) = Some(public_health) {
    cfg.route(\"/if-let\", web::get().to(health));
} else {
    cfg.route(\"/if-let-else\", web::get().to(health));
}
cfg.route(\"/after-if\", web::get().to(health));
while let Some(health) = None::<fn()> {
    cfg.route(\"/while-let\", web::get().to(health));
}
cfg.route(\"/after-while\", web::get().to(health));
if let Some(health) = Some(cfg.route(\"/first-scrutinee\", web::get().to(health)))
    && let Some(_) = Some(cfg.route(\"/chain-scrutinee\", web::get().to(health)))
{
    cfg.route(\"/let-chain\", web::get().to(health));
}
[public_health].into_iter().for_each(|health| {
    cfg.route(\"/closure-param\", web::get().to(health));
});
cfg.route(\"/after-closure\", web::get().to(health));
{
    const health: u8 = 5;
    cfg.route(\"/const\", web::get().to(health));
}
{
    static health: u8 = 5;
    cfg.route(\"/static\", web::get().to(health));
}
{
    async fn health() { require_admin(); }
    let health = public_health;
    cfg.route(\"/let-over-item\", web::get().to(health));
}
let health = public_health;
let mut later = || cfg.route(\"/captured\", web::get().to(health));
{
    async fn health() { require_admin(); }
    cfg.route(\"/inner-item\", web::get().to(health));
}
cfg.route(\"/outer-let\", web::get().to(health));
}";
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let line_of = |needle: &str| {
        source
            .lines()
            .position(|line| line.contains(needle))
            .map(|index| index + 1)
            .unwrap()
    };
    let module_health = line_of("async fn health() { require_admin(); }");
    let inner_item = source
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("async fn health() { require_admin(); }"))
        .map(|(index, _)| index + 1)
        .last()
        .unwrap();
    assert!(inner_item > module_health);
    assert!(inner_item < line_of("\"/inner-item\""));

    let file = Path::new("shadowing.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let route = |path: &str| {
        visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    };

    // Every binding form shadows the protected module-level `health`.
    for path in [
        "/method-param",
        "/param",
        "/closure",
        "/variable",
        "/after-let",
        "/destructured",
        "/struct-pattern",
        "/for",
        "/match",
        "/if-let",
        "/while-let",
        "/chain-scrutinee",
        "/let-chain",
        "/closure-param",
        "/const",
        "/static",
        "/let-over-item",
        "/captured",
        "/outer-let",
    ] {
        let route = route(path);
        assert_eq!(
            route.handler_resolution,
            Some(HandlerResolution::Unresolved),
            "{path}"
        );
        assert!(route.authorization.is_empty(), "{path}");
        assert!(!route.is_authorized(), "{path}");
    }

    // Before a binding, inside its own initializer, in sibling branches, and
    // after its scope ends, `health` is still the module-level handler.
    for path in [
        "/unshadowed",
        "/before-let",
        "/own-initializer",
        "/after-for",
        "/other-arm",
        "/after-match",
        "/if-let-else",
        "/after-if",
        "/after-while",
        "/first-scrutinee",
        "/after-closure",
    ] {
        let route = route(path);
        assert_eq!(
            route.handler_resolution,
            Some(HandlerResolution::Local),
            "{path}"
        );
        assert_eq!(route.authorization.len(), 1, "{path}");
        assert_eq!(route.authorization[0].line, module_health, "{path}");
    }

    // Qualified paths bypass local bindings.
    for path in ["/qualified", "/crate-qualified"] {
        let route = route(path);
        assert_eq!(
            route.handler_resolution,
            Some(HandlerResolution::Qualified),
            "{path}"
        );
        assert_eq!(route.authorization[0].line, module_health, "{path}");
    }

    // An inner block's item shadows the outer `let`.
    let inner = route("/inner-item");
    assert_eq!(inner.handler_resolution, Some(HandlerResolution::Local));
    assert_eq!(inner.authorization.len(), 1);
    assert_eq!(inner.authorization[0].line, inner_item);
}

#[test]
fn shadowed_handler_names_never_use_the_unique_name_fallback() {
    let repo = TempRepo::new(
        "shadowed-fallback",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/handlers.rs",
                "fn require_admin() {}
pub async fn health() { require_admin(); }
",
            ),
            (
                "src/main.rs",
                "mod handlers;
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/fallback\", web::get().to(health));
let health = || async {};
cfg.route(\"/closure\", web::get().to(health));
cfg.route(\"/qualified\", web::get().to(handlers::health));
}
fn register<H>(cfg: &mut web::ServiceConfig, health: H) {
cfg.route(\"/param\", web::get().to(health));
}
fn configure_loop(cfg: &mut web::ServiceConfig) {
for health in [handlers::health] {
    cfg.route(\"/for\", web::get().to(health));
}
}
",
            ),
        ],
    );
    let report = repo.analyze();

    assert_resolved_evidence(
        route_at(&report, "/fallback"),
        HandlerResolution::UniqueName,
        "src/handlers.rs",
    );
    assert_resolved_evidence(
        route_at(&report, "/qualified"),
        HandlerResolution::Qualified,
        "src/handlers.rs",
    );
    for path in ["/closure", "/param", "/for"] {
        let route = route_at(&report, path);
        assert_eq!(resolution(route), &HandlerResolution::Unresolved, "{path}");
        assert!(route.authorization.is_empty(), "{path}");
    }
}

struct TempRepo(PathBuf);

impl TempRepo {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!("archer-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (path, contents) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        Self(root)
    }

    fn analyze(&self) -> Report {
        analyze_repository(&self.0).unwrap()
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const CARGO_TOML: &str = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n";

fn route_at<'a>(report: &'a Report, path: &str) -> &'a Route {
    report
        .routes
        .iter()
        .find(|route| route.path == path)
        .unwrap_or_else(|| panic!("missing route {path}"))
}

fn resolution(route: &Route) -> &HandlerResolution {
    route.handler_resolution.as_ref().unwrap()
}

fn assert_resolved_evidence(route: &Route, expected: HandlerResolution, file_suffix: &str) {
    assert_eq!(
        resolution(route),
        &expected,
        "resolution for {}",
        route.path
    );
    assert_eq!(route.authorization.len(), 1, "evidence for {}", route.path);
    assert_eq!(route.authorization[0].mechanism, "require_admin");
    assert!(
        route.authorization[0].file.ends_with(file_suffix),
        "evidence for {} came from {}",
        route.path,
        route.authorization[0].file.display()
    );
    assert!(route.is_authorized());
}

#[test]
fn cross_file_glob_imported_handlers_carry_definition_evidence() {
    let repo = TempRepo::new(
        "cross-file",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/handlers.rs",
                "pub fn require_admin() {}
pub async fn users() { require_admin(); }
pub async fn orders() { require_admin(); }
pub async fn reports() { require_admin(); }
pub async fn payments() {}
",
            ),
            (
                "src/main.rs",
                "mod handlers;
use crate::handlers::*;
fn configure(cfg: &mut web::ServiceConfig) {
cfg.service(web::scope(\"/admin\")
    .route(\"/users\", web::get().to(users))
    .route(\"/orders\", web::get().to(orders))
    .route(\"/reports\", web::get().to(reports))
    .route(\"/payments\", web::get().to(payments)));
}
",
            ),
        ],
    );
    let report = repo.analyze();

    assert_eq!(report.routes.len(), 4);
    for path in ["/admin/users", "/admin/orders", "/admin/reports"] {
        let route = route_at(&report, path);
        assert_resolved_evidence(route, HandlerResolution::GlobImported, "src/handlers.rs");
        assert!(route.file.ends_with("src/main.rs"));
    }
    let users = route_at(&report, "/admin/users");
    assert_eq!(users.authorization[0].line, 2);
    assert_eq!(users.authorization[0].handler.as_deref(), Some("users"));

    let payments = route_at(&report, "/admin/payments");
    assert_eq!(resolution(payments), &HandlerResolution::GlobImported);
    assert!(payments.authorization.is_empty());

    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].suspicious_route.path,
        "/admin/payments"
    );
    assert_eq!(report.finding_details[0].authorized_peer_routes.len(), 3);
}

#[test]
fn module_qualified_handlers_resolve_through_file_and_inline_modules() {
    let repo = TempRepo::new(
        "qualified",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/handlers/mod.rs", "pub mod admin;\n"),
            (
                "src/handlers/admin.rs",
                "fn require_admin() {}
pub async fn users() { require_admin(); }
pub async fn orders() { require_admin(); }
",
            ),
            (
                "src/main.rs",
                "mod handlers;
mod routes;
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/root-relative\", web::get().to(handlers::admin::users));
}
",
            ),
            (
                "src/routes.rs",
                "use crate::handlers::admin;
async fn health() {}
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/crate\", web::get().to(crate::handlers::admin::users))
    .route(\"/super\", web::get().to(super::handlers::admin::orders))
    .route(\"/module-alias\", web::get().to(admin::orders))
    .route(\"/self\", web::get().to(self::health));
}
mod nested {
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/nested-super\", web::get().to(super::super::handlers::admin::users));
}
}
",
            ),
        ],
    );
    let report = repo.analyze();

    for path in [
        "/root-relative",
        "/crate",
        "/super",
        "/module-alias",
        "/nested-super",
    ] {
        assert_resolved_evidence(
            route_at(&report, path),
            HandlerResolution::Qualified,
            "src/handlers/admin.rs",
        );
    }
    let crate_route = route_at(&report, "/crate");
    assert_eq!(crate_route.handler.as_deref(), Some("users"));
    assert_eq!(
        crate_route.handler_path.as_deref(),
        Some("crate::handlers::admin::users")
    );

    let health = route_at(&report, "/self");
    assert_eq!(resolution(health), &HandlerResolution::Qualified);
    assert!(health.authorization.is_empty());
}

#[test]
fn explicit_imports_renames_and_reexports_resolve_to_the_named_definition() {
    let repo = TempRepo::new(
        "imports",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/handlers/mod.rs",
                "pub mod admin;
pub mod public;
pub use public::list as public_list;
",
            ),
            (
                "src/handlers/admin.rs",
                "fn require_admin() {}
pub async fn list() { require_admin(); }
",
            ),
            ("src/handlers/public.rs", "pub async fn list() {}\n"),
            (
                "src/main.rs",
                "mod handlers;
use crate::handlers::admin::list as admin_list;
use crate::handlers::public::{self, list};
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/renamed\", web::get().to(admin_list))
    .route(\"/grouped\", web::get().to(list))
    .route(\"/self-import\", web::get().to(public::list))
    .route(\"/reexport\", web::get().to(handlers::public_list));
}
",
            ),
        ],
    );
    let report = repo.analyze();

    let renamed = route_at(&report, "/renamed");
    assert_resolved_evidence(
        renamed,
        HandlerResolution::Imported,
        "src/handlers/admin.rs",
    );
    assert_eq!(renamed.handler.as_deref(), Some("admin_list"));
    assert_eq!(renamed.authorization[0].handler.as_deref(), Some("list"));

    let grouped = route_at(&report, "/grouped");
    assert_eq!(resolution(grouped), &HandlerResolution::Imported);
    assert!(grouped.authorization.is_empty());

    for path in ["/self-import", "/reexport"] {
        let route = route_at(&report, path);
        assert_eq!(resolution(route), &HandlerResolution::Qualified, "{path}");
        assert!(route.authorization.is_empty(), "{path}");
    }
}

#[test]
fn duplicate_handler_names_never_share_evidence() {
    let repo = TempRepo::new(
        "duplicates",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/handlers/mod.rs", "pub mod admin;\npub mod public;\n"),
            (
                "src/handlers/admin.rs",
                "fn require_admin() {}
pub async fn list() { require_admin(); }
",
            ),
            ("src/handlers/public.rs", "pub async fn list() {}\n"),
            (
                "src/main.rs",
                "mod handlers;
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/admin/list\", web::get().to(handlers::admin::list))
    .route(\"/public/list\", web::get().to(handlers::public::list));
}
",
            ),
        ],
    );
    let report = repo.analyze();

    assert_resolved_evidence(
        route_at(&report, "/admin/list"),
        HandlerResolution::Qualified,
        "src/handlers/admin.rs",
    );
    let public = route_at(&report, "/public/list");
    assert_eq!(resolution(public), &HandlerResolution::Qualified);
    assert!(public.authorization.is_empty());
    assert!(!public.is_authorized());
}

#[test]
fn same_file_inline_modules_with_duplicate_names_do_not_create_false_drift() {
    let repo = TempRepo::new(
        "inline-duplicates",
        &[(
            "src/main.rs",
            "fn require_admin() {}
mod admin { pub async fn list() { super::require_admin(); } }
mod public { pub async fn list() {} }
async fn users() { require_admin(); }
async fn orders() { require_admin(); }
fn configure(cfg: &mut web::ServiceConfig) {
cfg.service(web::scope(\"/admin\")
    .route(\"/users\", web::get().to(users))
    .route(\"/orders\", web::get().to(orders))
    .route(\"/list\", web::get().to(admin::list)));
cfg.service(web::scope(\"/public\").route(\"/list\", web::get().to(public::list)));
}
",
        )],
    );
    let report = repo.analyze();

    assert_resolved_evidence(
        route_at(&report, "/admin/list"),
        HandlerResolution::Qualified,
        "src/main.rs",
    );
    assert_eq!(
        resolution(route_at(&report, "/admin/users")),
        &HandlerResolution::Local
    );
    assert!(route_at(&report, "/public/list").authorization.is_empty());
    assert!(report.finding_details.is_empty());
}

#[test]
fn ambiguous_handlers_attach_no_evidence_and_list_sorted_candidates() {
    let repo = TempRepo::new(
        "ambiguous",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/handlers/mod.rs", "pub mod admin;\npub mod public;\n"),
            (
                "src/handlers/admin.rs",
                "fn require_admin() {}
pub async fn list() { require_admin(); }
pub async fn audit() { require_admin(); }
",
            ),
            ("src/handlers/public.rs", "pub async fn list() {}\n"),
            (
                "src/main.rs",
                "mod handlers;
mod routes;
use crate::handlers::public::*;
use crate::handlers::admin::*;
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/glob-ambiguous\", web::get().to(list));
}
",
            ),
            (
                "src/routes.rs",
                "fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/fallback-ambiguous\", web::get().to(list))
    .route(\"/unique\", web::get().to(audit))
    .route(\"/compatible-qualifier\", web::get().to(crate::handlers::audit))
    .route(\"/incompatible-qualifier\", web::get().to(crate::handlers::public::audit));
}
",
            ),
        ],
    );
    let report = repo.analyze();

    let expected = HandlerResolution::Ambiguous {
        candidates: vec![
            "crate::handlers::admin::list".into(),
            "crate::handlers::public::list".into(),
        ],
    };
    for path in ["/glob-ambiguous", "/fallback-ambiguous"] {
        let route = route_at(&report, path);
        assert_eq!(resolution(route), &expected, "{path}");
        assert!(route.authorization.is_empty(), "{path}");
        assert!(!route.is_authorized(), "{path}");
    }

    for path in ["/unique", "/compatible-qualifier"] {
        assert_resolved_evidence(
            route_at(&report, path),
            HandlerResolution::UniqueName,
            "src/handlers/admin.rs",
        );
    }
    let incompatible = route_at(&report, "/incompatible-qualifier");
    assert_eq!(resolution(incompatible), &HandlerResolution::Unresolved);
    assert!(incompatible.authorization.is_empty());

    let first = serde_json::to_string(&report).unwrap();
    let second = serde_json::to_string(&repo.analyze()).unwrap();
    assert_eq!(first, second);
}

#[test]
fn unresolved_handlers_stay_in_inventory_without_evidence() {
    let repo = TempRepo::new(
        "unresolved",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/other.rs",
                "fn require_admin() {}
pub async fn h() { require_admin(); }
pub async fn imported() { require_admin(); }
",
            ),
            (
                "src/main.rs",
                "mod other;
use other_crate::imported;
struct Handlers;
impl Handlers { async fn list() { require_admin(); } }
async fn list() { require_admin(); }
fn configure(cfg: &mut web::ServiceConfig) {
cfg.route(\"/external\", web::get().to(other_crate::h))
    .route(\"/absolute\", web::get().to(::other_crate::h))
    .route(\"/explicit-external-import\", web::get().to(imported))
    .route(\"/method\", web::get().to(Handlers::list))
    .route(\"/closure\", web::get().to(|| async { \"ok\" }))
    .route(\"/missing\", web::get().to(missing_handler))
    .route(\"/no-handler\", web::get());
}
",
            ),
        ],
    );
    let report = repo.analyze();

    assert_eq!(report.routes.len(), 7);
    for path in [
        "/external",
        "/absolute",
        "/explicit-external-import",
        "/method",
        "/missing",
    ] {
        let route = route_at(&report, path);
        assert_eq!(resolution(route), &HandlerResolution::Unresolved, "{path}");
        assert!(route.authorization.is_empty(), "{path}");
        assert!(!route.is_authorized(), "{path}");
        assert!(!route.unverified.is_empty(), "{path}");
    }
    // A closure handler is analysed in place; this one checks nothing.
    let closure = route_at(&report, "/closure");
    assert_eq!(resolution(closure), &HandlerResolution::Closure);
    assert!(closure.authorization.is_empty());
    assert!(closure.unverified.is_empty());

    let method = route_at(&report, "/method");
    assert_eq!(method.handler.as_deref(), Some("list"));
    assert_eq!(method.handler_path.as_deref(), Some("Handlers::list"));
    assert_eq!(
        route_at(&report, "/absolute").handler_path.as_deref(),
        Some("::other_crate::h")
    );

    let closure = route_at(&report, "/closure");
    assert!(closure.handler.is_none());
    assert!(closure.handler_path.is_none());

    let no_handler = route_at(&report, "/no-handler");
    assert!(no_handler.handler.is_none());
    assert!(no_handler.handler_resolution.is_none());
}

#[test]
fn attribute_routes_use_their_own_definition_evidence() {
    let repo = TempRepo::new(
        "attributes",
        &[(
            "src/main.rs",
            "fn require_admin() {}
mod admin { pub async fn users() { super::require_admin(); } }
#[get(\"/users\")]
async fn users() {}
mod secure {
#[get(\"/secure\")]
async fn users() { crate::require_admin(); }
}
fn app() { App::new().service(users).service(secure::users); }
",
        )],
    );
    let report = repo.analyze();

    let open = route_at(&report, "/users");
    assert_eq!(resolution(open), &HandlerResolution::Definition);
    assert!(open.authorization.is_empty());

    let secure = route_at(&report, "/secure");
    assert_eq!(resolution(secure), &HandlerResolution::Definition);
    assert_eq!(secure.authorization.len(), 1);
    assert_eq!(secure.authorization[0].mechanism, "require_admin");
    assert_eq!(secure.authorization[0].line, 7);
}

#[test]
fn handler_resolution_serializes_as_tagged_kind() {
    assert_eq!(
        serde_json::to_value(HandlerResolution::Local).unwrap(),
        serde_json::json!({"kind": "Local"})
    );
    assert_eq!(
        serde_json::to_value(HandlerResolution::Ambiguous {
            candidates: vec!["crate::a::list".into()]
        })
        .unwrap(),
        serde_json::json!({"kind": "Ambiguous", "candidates": ["crate::a::list"]})
    );
}

#[test]
fn module_location_follows_cargo_layout() {
    let repo = TempRepo::new(
        "layout",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/main.rs", ""),
            ("src/lib.rs", ""),
            ("src/handlers/mod.rs", ""),
            ("src/handlers/admin.rs", ""),
            ("src/bin/tool.rs", ""),
            ("tests/integration.rs", ""),
            ("build.rs", ""),
        ],
    );
    let root = &repo.0;
    let module = |path: &str| module_location(root, &root.join(path));

    assert_eq!(module("src/main.rs"), (root.clone(), vec![]));
    assert_eq!(module("src/lib.rs"), (root.clone(), vec![]));
    assert_eq!(
        module("src/handlers/mod.rs"),
        (root.clone(), vec!["handlers".into()])
    );
    assert_eq!(
        module("src/handlers/admin.rs"),
        (root.clone(), vec!["handlers".into(), "admin".into()])
    );
    for isolated in ["src/bin/tool.rs", "tests/integration.rs", "build.rs"] {
        assert_eq!(
            module(isolated),
            (root.join(isolated), vec![]),
            "{isolated}"
        );
    }
}

fn macro_evidence(
    source: &str,
) -> HashMap<String, Vec<(AuthEvidenceKind, String, String, AuthStrength)>> {
    let syntax: syn::File = syn::parse_str(source).unwrap();
    collect_authorized_handlers(Path::new("macros.rs"), &syntax)
        .into_iter()
        .map(|(handler, evidence)| {
            let evidence = evidence
                .into_iter()
                .map(|item| {
                    assert_eq!(item.handler.as_deref(), Some(handler.as_str()));
                    (
                        item.kind,
                        item.mechanism,
                        item.symbol.unwrap(),
                        item.strength,
                    )
                })
                .collect();
            (handler, evidence)
        })
        .collect()
}

#[test]
fn statement_and_expression_macros_use_the_helper_name_rules() {
    let evidence = macro_evidence(
        r#"
        fn statement() { require_admin!(user); }
        fn braced() { check_admin! { user } }
        fn expression() { let allowed = check_permission!(user, "reports:read"); if !allowed { return; } }
        fn tail() -> Result<(), E> { has_role!(user, "manager") }
        fn condition() { if !is_owner!(user, document) { return; } }
        fn ownership() { ensure_owner!(user, document); }
        fn authentication() { require_auth!(request); }
        "#,
    );
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    let single = |handler: &str| {
        assert_eq!(evidence[handler].len(), 1, "{handler}");
        evidence[handler][0].clone()
    };

    assert_eq!(
        single("statement"),
        (
            RoleCheck,
            "require_admin".into(),
            "require_admin!".into(),
            Strong
        )
    );
    assert_eq!(
        single("braced"),
        (
            RoleCheck,
            "check_admin".into(),
            "check_admin!".into(),
            Strong
        )
    );
    assert_eq!(
        single("expression"),
        (
            PermissionCheck,
            "check_permission".into(),
            "check_permission!".into(),
            Strong
        )
    );
    assert_eq!(
        single("tail"),
        (RoleCheck, "has_role".into(), "has_role!".into(), Strong)
    );
    assert_eq!(
        single("condition"),
        (
            OwnershipCheck,
            "is_owner".into(),
            "is_owner!".into(),
            Medium
        )
    );
    assert_eq!(
        single("ownership"),
        (
            OwnershipCheck,
            "ensure_owner".into(),
            "ensure_owner!".into(),
            Medium
        )
    );
    assert_eq!(
        single("authentication"),
        (
            IdentityExtraction,
            "require_auth".into(),
            "require_auth!".into(),
            Weak
        )
    );

    let syntax: syn::File =
        syn::parse_str("fn admin() {\n    log::info!(\"start\");\n    require_admin!(user);\n}")
            .unwrap();
    let line = collect_authorized_handlers(Path::new("macros.rs"), &syntax)["admin"][0].line;
    assert_eq!(line, 3);
}

#[test]
fn logging_formatting_and_unrelated_macros_are_not_evidence() {
    let evidence = macro_evidence(
        r#"
        fn output(user: &str) {
            println!("admin {}", user);
            let message = format!("role: {}", user);
            info!("permission check for {}", user);
            log::warn!("admin access denied");
            tracing::debug!(role = "admin");
            eprintln!("{}", message);
        }
        fn assertions(user: &User) {
            debug_assert!(has_role(user, "admin"));
            assert_eq!(user.role, "admin");
            let roles = vec![require_admin()];
        }
        fn names() {
            check_admin_log!(user);
            ensure_admin_exists!(user);
            role_name!(user);
            log_permission_check!(user);
            admin_dashboard!();
            verify_access_token!(token);
        }
        fn definitions() {
            macro_rules! require_admin { () => { require_admin() }; }
        }
        "#,
    );
    assert!(evidence.is_empty(), "{evidence:?}");
}

#[test]
fn qualified_macro_paths_use_their_last_segment() {
    let evidence = macro_evidence(
        r#"
        fn module() { auth::require_admin!(user); }
        fn crate_path() { crate::guards::check_permission!(user, "write"); }
        fn absolute() { ::authz::authorize!(user, action); }
        fn logging() { guards::admin::info!("checked"); }
        "#,
    );
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    assert_eq!(
        evidence["module"],
        vec![(
            RoleCheck,
            "require_admin".into(),
            "auth::require_admin!".into(),
            Strong
        )]
    );
    assert_eq!(
        evidence["crate_path"],
        vec![(
            PermissionCheck,
            "check_permission".into(),
            "crate::guards::check_permission!".into(),
            Strong
        )]
    );
    assert_eq!(
        evidence["absolute"],
        vec![(
            ManualAuthorizationCheck,
            "authorize".into(),
            "::authz::authorize!".into(),
            Strong
        )]
    );
    assert!(!evidence.contains_key("logging"));
}

#[test]
fn macro_evidence_stays_with_its_own_handler() {
    let evidence = route_evidence(
        r#"
        async fn outer() {
            fn nested() { require_admin!(user); }
            struct Helper;
            impl Helper { fn check(&self) { check_permission!(user); } }
            trait Policy { fn verify(&self) { authorize!(user); } }
            macro_rules! hidden { () => { require_admin!(user) }; }
        }
        async fn protected() { require_admin!(user); }
        async fn sibling() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/outer", web::get().to(outer))
                .route("/protected", web::get().to(protected))
                .route("/sibling", web::get().to(sibling)));
        }
        "#,
    );
    assert!(
        evidence["/admin/outer"].is_empty(),
        "{:?}",
        evidence["/admin/outer"]
    );
    assert_eq!(
        evidence["/admin/protected"],
        vec![(AuthEvidenceKind::RoleCheck, "require_admin".to_owned())]
    );
    assert!(evidence["/admin/sibling"].is_empty());
}

#[test]
fn macro_handler_and_middleware_evidence_are_kept_once_each() {
    let source = r#"
        fn check_permission() {}
        async fn users() {
            require_admin!(user);
            check_permission();
            log::info!("users");
        }
        async fn orders() { require_admin!(user); }
        async fn reports() { require_admin!(user); }
        async fn payments() { log::info!("payments"); }
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/users", web::get().guard(RoleGuard).to(users))
                .route("/orders", web::get().to(orders))
                .route("/reports", web::get().to(reports))
                .route("/payments", web::get().to(payments))
                .wrap(AuthMiddleware));
        }
    "#;
    let evidence = route_evidence(source);
    use AuthEvidenceKind::*;
    let identity = (IdentityExtraction, "AuthMiddleware".to_owned());
    let role_macro = (RoleCheck, "require_admin".to_owned());
    assert_eq!(
        evidence["/admin/users"],
        vec![
            (AuthorizationGuard, "RoleGuard".to_owned()),
            role_macro.clone(),
            (PermissionCheck, "check_permission".to_owned()),
            identity.clone(),
        ]
    );
    for path in ["/admin/orders", "/admin/reports"] {
        assert_eq!(
            evidence[path],
            vec![role_macro.clone(), identity.clone()],
            "{path}"
        );
    }
    assert_eq!(evidence["/admin/payments"], vec![identity]);

    // Macro evidence feeds drift inference like any other handler evidence.
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let (_, _, details, _) = build_analysis_layers(&visitor.routes);
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].suspicious_route.path, "/admin/payments");
    assert_eq!(details[0].authorized_peer_routes.len(), 3);
}

const A6_PROBE: &str = include_str!("../../tests/fixtures/probes/a6_target_dir_scanned.rs");

#[test]
fn build_output_and_test_directories_are_not_scanned() {
    let repo = TempRepo::new(
        "a6-skip-dirs",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/main.rs", A6_PROBE),
            ("target/debug/build/gen.rs", A6_PROBE),
            (".git/hooks/gen.rs", A6_PROBE),
            ("tests/it.rs", A6_PROBE),
        ],
    );

    let report = repo.analyze();
    assert_eq!(report.files_scanned, 1);
    assert_eq!(report.routes.len(), 3);

    let options = AnalysisOptions {
        include_tests: true,
        ..AnalysisOptions::default()
    };
    let report = analyze_repository_with(&repo.0, &options).unwrap();
    assert_eq!(report.files_scanned, 2);
    assert_eq!(report.routes.len(), 6);
}

#[test]
fn unreadable_file_is_reported_and_skipped() {
    let repo = TempRepo::new(
        "a7-unreadable",
        &[(
            "valid.rs",
            "fn configure(cfg: &mut web::ServiceConfig) { cfg.route(\"/users\", web::get()); }",
        )],
    );
    fs::write(repo.0.join("latin1.rs"), b"// caf\xe9\nfn main() {}\n").unwrap();

    let report = repo.analyze();
    assert_eq!(report.parse_errors.len(), 1);
    assert!(report.parse_errors[0].contains("latin1.rs"));
    assert!(report.parse_errors[0].contains("failed to read"));
    assert_eq!(report.routes.len(), 1);
}

#[test]
fn routes_are_reported_in_source_order() {
    let repo = TempRepo::new(
        "c5-order",
        &[(
            "main.rs",
            "fn configure(cfg: &mut web::ServiceConfig) {
                cfg.service(web::scope(\"/admin\")
                    .route(\"/users\", web::get().to(users))
                    .route(\"/orders\", web::get().to(orders)).route(\"/payments\", web::get().to(payments)));
            }",
        )],
    );

    let paths: Vec<_> = repo
        .analyze()
        .routes
        .into_iter()
        .map(|route| route.path)
        .collect();
    assert_eq!(paths, ["/admin/users", "/admin/orders", "/admin/payments"]);
}

#[test]
fn attribute_routes_take_prefix_and_middleware_from_their_registering_scope() {
    let repo = TempRepo::new(
        "a1-attribute-scope",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/main.rs",
                include_str!("../../tests/fixtures/probes/a1_attribute_routes_in_scope.rs"),
            ),
            (
                "src/ops.rs",
                "use crate::health;
                 fn configure(cfg: &mut web::ServiceConfig) {
                     cfg.service(web::scope(\"/ops\").wrap(RequireAdminMiddleware).service(health));
                 }",
            ),
        ],
    );

    let report = repo.analyze();
    let payments = route_at(&report, "/admin/payments");
    assert_eq!(payments.scope_prefix, "/admin");
    assert!(report.routes.iter().all(|route| route.path != "/payments"));

    // `health` is registered at the application root and under `/ops`.
    let ops_health = route_at(&report, "/ops/health");
    assert!(
        ops_health
            .authorization
            .iter()
            .any(|evidence| evidence.mechanism == "RequireAdminMiddleware")
    );
    assert!(route_at(&report, "/health").authorization.is_empty());

    let flagged: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| finding.suspicious_route.path.as_str())
        .collect();
    assert_eq!(flagged, ["/admin/payments"]);
}

#[test]
fn configure_inside_scope_inherits_prefix_and_middleware() {
    let repo = TempRepo::new(
        "a2-configure",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/main.rs",
                include_str!("../../tests/fixtures/probes/a2_configure_in_scope.rs"),
            ),
        ],
    );

    let report = repo.analyze();
    let paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    assert_eq!(paths, ["/admin/users", "/admin/orders", "/admin/payments"]);
    for route in &report.routes {
        assert_eq!(route.scope_prefix, "/admin");
        assert!(
            route.authorization.iter().any(|evidence| {
                evidence.kind == AuthEvidenceKind::AuthorizationMiddleware
                    && evidence.mechanism == "RequireAdminMiddleware"
            }),
            "{}",
            route.path
        );
    }
}

#[test]
fn recursive_configure_does_not_loop() {
    let repo = TempRepo::new(
        "a2-configure-recursive",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/main.rs",
                "fn a(cfg: &mut web::ServiceConfig) { cfg.route(\"/a\", web::get().to(h)).configure(b); }
                 fn b(cfg: &mut web::ServiceConfig) { cfg.route(\"/b\", web::get().to(h)).configure(a); }
                 fn main() { App::new().service(web::scope(\"/x\").configure(a)); }",
            ),
        ],
    );

    let mut paths: Vec<_> = repo
        .analyze()
        .routes
        .into_iter()
        .map(|route| route.path)
        .collect();
    paths.sort();
    assert_eq!(paths, ["/x/a", "/x/b"]);
}

#[test]
fn qualified_and_multi_method_route_attributes_are_extracted() {
    let repo = TempRepo::new(
        "a3-attributes",
        &[(
            "main.rs",
            "#[actix_web::get(\"/x\")] async fn x() {}
             #[route(\"/y\", method = \"GET\", method = \"POST\")] async fn y() {}
             #[get(\"/z\", wrap = \"Logger::default()\")] async fn z() {}
             fn app() { App::new().service(x).service(y).service(z); }",
        )],
    );

    let routes: Vec<_> = repo
        .analyze()
        .routes
        .into_iter()
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    assert_eq!(routes, ["GET /x", "GET /y", "POST /y", "GET /z"]);
}

#[test]
fn resource_to_registers_an_any_method_route() {
    let repo = TempRepo::new(
        "a4-resource-to",
        &[(
            "main.rs",
            "fn handler() {} fn h() {}
             fn configure(cfg: &mut web::ServiceConfig) {
                 cfg.service(web::resource(\"/res\").wrap(AdminGuard).to(handler))
                    .service(web::resource(\"/r2\").route(web::get().to(h)));
             }",
        )],
    );

    let report = repo.analyze();
    let routes: Vec<_> = report
        .routes
        .iter()
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    assert_eq!(routes, ["UNKNOWN /res", "GET /r2"]);
    let resource = route_at(&report, "/res");
    assert_eq!(resource.handler.as_deref(), Some("handler"));
    assert!(
        resource
            .authorization
            .iter()
            .any(|evidence| evidence.mechanism == "AdminGuard")
    );
}

#[test]
fn const_paths_resolve_and_unresolved_paths_are_kept_with_a_warning() {
    let repo = TempRepo::new(
        "a5-const-paths",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/main.rs",
                "mod paths;
                 use paths::ORDERS;
                 const ADMIN: &str = \"/admin\";
                 const USERS: &str = \"/users\";
                 async fn a() { require_admin(); } async fn b() { require_admin(); } async fn c() {}
                 fn main() {
                     App::new().service(web::scope(ADMIN)
                         .route(USERS, web::get().to(a))
                         .route(ORDERS, web::get().to(b))
                         .route(paths::REPORTS, web::get().to(a))
                         .route(MISSING, web::get().to(c)));
                 }",
            ),
            (
                "src/paths.rs",
                "pub const ORDERS: &str = \"/orders\"; pub const REPORTS: &str = \"/reports\";",
            ),
        ],
    );

    let report = repo.analyze();
    let paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/admin/users",
            "/admin/orders",
            "/admin/reports",
            "/admin/<unresolved:MISSING>"
        ]
    );
    assert_eq!(
        report.warnings.iter().filter(|warning| warning.contains("MISSING")).count(),
        1
    );
    // A route whose path is unknown is not compared with peers, and says so.
    assert!(report.finding_details.is_empty());
    assert!(report.unjudged.iter().any(|route| {
        route.path == "/admin/<unresolved:MISSING>" && route.reason == UnjudgedReason::UnresolvedPath
    }));
    assert!(
        report
            .peer_groups
            .iter()
            .flat_map(|group| &group.routes)
            .all(|route| !route.path.contains("unresolved"))
    );
}

fn signature_evidence(source: &str) -> Vec<(AuthEvidenceKind, String)> {
    let item: syn::ItemFn = syn::parse_str(source).unwrap();
    handler_evidence(Path::new("extractors.rs"), &item)
        .into_iter()
        .map(|evidence| (evidence.kind, evidence.mechanism))
        .collect()
}

#[test]
fn authorization_extractors_in_handler_signatures_are_evidence() {
    use AuthEvidenceKind::*;
    assert_eq!(
        signature_evidence("async fn users(_admin: AdminUser) {}"),
        [(RoleCheck, "AdminUser".to_owned())]
    );
    assert_eq!(
        signature_evidence("async fn users(_: RequireRole<Admin>) {}"),
        [(RoleCheck, "RequireRole".to_owned())]
    );
    assert_eq!(
        signature_evidence("async fn users(_: web::ReqData<PermissionsGuard>) {}"),
        []
    );
    assert_eq!(
        signature_evidence("async fn users(auth: BearerAuth) {}"),
        [(IdentityExtraction, "BearerAuth".to_owned())]
    );
    assert_eq!(
        signature_evidence(
            "async fn update(body: web::Json<RoleUpdate>, roles: web::Data<RoleService>, id: web::Path<u32>) {}"
        ),
        []
    );

    let repo = TempRepo::new(
        "b1-extractors",
        &[(
            "main.rs",
            include_str!("../../tests/fixtures/probes/b1_b2_extractors_and_attributes.rs"),
        )],
    );
    let report = repo.analyze();
    assert!(route_at(&report, "/admin/users").is_authorized());
    assert!(route_at(&report, "/admin/orders").is_authorized());
}

#[test]
fn authorization_attribute_macros_are_evidence() {
    let item: syn::ItemFn = syn::parse_str(
        "#[protect(\"ROLE_ADMIN\")] #[get(\"/r\")] #[instrument] async fn reports() {}",
    )
    .unwrap();
    let evidence = handler_evidence(Path::new("attributes.rs"), &item);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].kind, AuthEvidenceKind::PermissionCheck);
    assert_eq!(evidence[0].mechanism, "protect");
    assert!(
        evidence[0]
            .symbol
            .as_deref()
            .unwrap()
            .contains("ROLE_ADMIN")
    );
    assert_eq!(evidence[0].strength, AuthStrength::Strong);

    let item: syn::ItemFn =
        syn::parse_str("#[actix_web_grants::has_roles(\"ADMIN\")] async fn users() {}").unwrap();
    let evidence = handler_evidence(Path::new("attributes.rs"), &item);
    assert_eq!(evidence[0].kind, AuthEvidenceKind::RoleCheck);
}

#[test]
fn unscoped_routes_with_different_leading_segments_are_not_peers() {
    let repo = TempRepo::new(
        "c1-unscoped",
        &[(
            "main.rs",
            include_str!("../../tests/fixtures/probes/c1_unscoped_prefixes.rs"),
        )],
    );

    let report = repo.analyze();
    assert!(report.finding_details.is_empty());
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.peer_groups[0].prefix, "/admin");
    let mut paths: Vec<_> = report.peer_groups[0]
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    paths.sort();
    assert_eq!(paths, ["/admin/orders", "/admin/users"]);
}

#[test]
fn routes_under_an_auth_prefix_are_still_analysed() {
    let users = route("GET", "/auth/admin/users", "/auth/admin", "PRESENT");
    let orders = route("GET", "/auth/admin/orders", "/auth/admin", "PRESENT");
    let purge = route("GET", "/auth/admin/purge", "/auth/admin", "NONE");
    assert!(!is_authentication_route(&purge));
    assert!(is_authentication_route(&route(
        "POST",
        "/auth/login",
        "/auth",
        "NONE"
    )));
    assert!(is_authentication_route(&route(
        "POST",
        "/api/token/{id}",
        "/api",
        "NONE"
    )));

    let details = build_analysis_layers(&[users, orders, purge]).2;
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].suspicious_route.path, "/auth/admin/purge");
}

fn options(min_support: usize, dominance_threshold: f64) -> AnalysisOptions {
    AnalysisOptions {
        min_support,
        dominance_threshold,
        ..AnalysisOptions::default()
    }
}

#[test]
fn minority_authorization_does_not_produce_findings() {
    let repo = TempRepo::new(
        "c2-minority",
        &[(
            "main.rs",
            include_str!("../../tests/fixtures/probes/c2_minority_authorization.rs"),
        )],
    );

    let report = repo.analyze();
    assert!(report.finding_details.is_empty());
    assert_eq!(report.invariants[0].strength, AuthStrength::Weak);

    let report = analyze_repository_with(&repo.0, &options(2, 0.25)).unwrap();
    assert_eq!(report.finding_details.len(), 5);
}

#[test]
fn threshold_edges_do_not_panic() {
    let routes = [
        route("GET", "/admin/users", "/admin", "PRESENT"),
        route("GET", "/admin/payments", "/admin", "NONE"),
    ];
    assert!(
        build_analysis_layers_with(&routes, &options(1, 1.0))
            .2
            .is_empty()
    );
    assert_eq!(
        build_analysis_layers_with(&routes, &options(1, 0.5))
            .2
            .len(),
        1
    );
    assert!(
        build_analysis_layers_with(&routes, &options(2, 0.5))
            .2
            .is_empty()
    );
}

#[test]
fn structured_findings_drive_text_and_json_omits_preformatted_findings() {
    let repo = TempRepo::new(
        "d2-findings",
        &[(
            "main.rs",
            include_str!("../../tests/fixtures/probes/a1_attribute_routes_in_scope.rs"),
        )],
    );
    let report = repo.analyze();
    assert_eq!(report.finding_details.len(), 1);
    let rendered: Vec<String> = report.finding_details.iter().map(format_finding).collect();
    assert_eq!(rendered, report.findings);

    let json = serde_json::to_value(&report).unwrap();
    assert!(json.get("findings").is_none());
    assert!(json.get("finding_details").is_some());
}

#[test]
fn evidence_kinds_and_strengths_have_readable_names() {
    assert_eq!(AuthEvidenceKind::RoleCheck.to_string(), "role check");
    assert_eq!(
        AuthEvidenceKind::AuthorizationMiddleware.to_string(),
        "authorization middleware"
    );
    assert_eq!(
        AuthEvidenceKind::IdentityExtraction.to_string(),
        "identity extraction (not authorization)"
    );
    assert_eq!(AuthStrength::Strong.to_string(), "strong");
}

#[test]
fn weaker_authorization_is_reported_separately_with_its_evidence() {
    let repo = TempRepo::new(
        "c3-weaker",
        &[(
            "main.rs",
            include_str!("../../tests/fixtures/probes/c3_weaker_evidence_kind.rs"),
        )],
    );

    let report = repo.analyze();
    assert_eq!(report.finding_details.len(), 1);
    let finding = &report.finding_details[0];
    assert_eq!(finding.category, FindingCategory::WeakerAuthorization);
    assert_eq!(finding.suspicious_route.path, "/admin/payments");
    assert_eq!(finding.suspicious_route_tier, EvidenceTier::Resource);
    assert_eq!(finding.expected_tier, EvidenceTier::Privilege);
    assert!(
        finding
            .suspicious_route_evidence
            .iter()
            .any(|evidence| evidence.kind == AuthEvidenceKind::OwnershipCheck)
    );
    let mut peers: Vec<_> = finding
        .authorized_peer_routes
        .iter()
        .map(|peer| peer.path.as_str())
        .collect();
    peers.sort();
    assert_eq!(peers, ["/admin/orders", "/admin/users"]);
    assert!(report.findings[0].contains("weaker authorization"));
}

#[test]
fn different_privilege_mechanisms_are_not_weaker() {
    let mut users = route("GET", "/admin/users", "/admin", "PRESENT");
    users.authorization[0].kind = AuthEvidenceKind::AuthorizationMiddleware;
    let orders = route("GET", "/admin/orders", "/admin", "PRESENT");
    let mut reports = route("GET", "/admin/reports", "/admin", "PRESENT");
    reports.authorization[0].kind = AuthEvidenceKind::PermissionCheck;
    let payments = route("GET", "/admin/payments", "/admin", "NONE");

    let details = build_analysis_layers(&[users, orders, reports, payments]).2;
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].category, FindingCategory::MissingAuthorization);
    assert_eq!(details[0].suspicious_route_tier, EvidenceTier::None);
}

fn fixture_report(name: &str, source: &str) -> Report {
    TempRepo::new(name, &[("Cargo.toml", CARGO_TOML), ("src/main.rs", source)]).analyze()
}

fn has_evidence(route: &Route, kind: AuthEvidenceKind, mechanism: &str) -> bool {
    route
        .authorization
        .iter()
        .any(|evidence| evidence.kind == kind && evidence.mechanism == mechanism)
}

fn finding_paths(report: &Report) -> Vec<&str> {
    report
        .finding_details
        .iter()
        .map(|finding| finding.suspicious_route.path.as_str())
        .collect()
}

#[test]
fn deeply_nested_builder_chains_do_not_overflow_the_stack() {
    let routes: String = (0..5000)
        .map(|index| format!("\n.route(\"/r{index}\", web::get().to(h))"))
        .collect();
    let report = fixture_report(
        "e1-deep-chain",
        &format!(
            "async fn h() {{}}\nfn main() {{ App::new().service(web::scope(\"/s\"){routes}); }}"
        ),
    );
    assert_eq!(report.routes.len(), 5000);
    assert_eq!(report.routes[0].path, "/s/r0");
}

#[test]
fn attribute_routes_registered_through_tuples_and_services_macro_take_the_scope() {
    let report = fixture_report(
        "e2-tuple-services",
        include_str!("../../tests/fixtures/probes/e2_tuple_and_services_macro.rs"),
    );
    let paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/admin/users",
            "/admin/orders",
            "/admin/payments",
            "/public/health"
        ]
    );
    assert!(has_evidence(
        route_at(&report, "/public/health"),
        AuthEvidenceKind::AuthorizationMiddleware,
        "RequireAdminMiddleware"
    ));
    assert_eq!(finding_paths(&report), ["/admin/payments"]);
}

#[test]
fn config_functions_called_directly_inherit_the_callers_scope() {
    for (name, source) in [
        (
            "e3-direct-call",
            include_str!("../../tests/fixtures/probes/e3_direct_config_call.rs"),
        ),
        (
            "e3-closure",
            include_str!("../../tests/fixtures/probes/e3_closure_configure.rs"),
        ),
    ] {
        let report = fixture_report(name, source);
        assert!(!report.routes.is_empty(), "{name}");
        for route in &report.routes {
            assert!(route.path.starts_with("/admin/"), "{name}: {}", route.path);
            assert_eq!(route.scope_prefix, "/admin", "{name}");
            assert!(
                has_evidence(
                    route,
                    AuthEvidenceKind::AuthorizationMiddleware,
                    "RequireAdminMiddleware"
                ),
                "{name}: {}",
                route.path
            );
        }
    }
}

#[test]
fn functions_returning_a_scope_are_expanded_where_they_are_registered() {
    let report = fixture_report(
        "e4-scope-fn",
        include_str!("../../tests/fixtures/probes/e4_scope_returning_function.rs"),
    );
    let paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "/api/admin/users",
            "/api/admin/orders",
            "/api/admin/payments"
        ]
    );
    for route in &report.routes {
        assert!(has_evidence(
            route,
            AuthEvidenceKind::AuthorizationMiddleware,
            "RequireAdminMiddleware"
        ));
    }
}

#[test]
fn wrap_fn_closures_are_middleware_evidence() {
    let report = fixture_report(
        "e5-wrap-fn",
        include_str!("../../tests/fixtures/probes/e5_wrap_fn.rs"),
    );
    for path in ["/admin/x", "/admin/y"] {
        assert!(
            has_evidence(
                route_at(&report, path),
                AuthEvidenceKind::AuthorizationMiddleware,
                "check_admin"
            ),
            "{path}"
        );
    }
    assert!(route_at(&report, "/staff/x").authorization.is_empty());
}

#[test]
fn method_guards_set_the_route_method() {
    let report = fixture_report(
        "e6-method-guards",
        include_str!("../../tests/fixtures/probes/e6_method_guards.rs"),
    );
    for route in &report.routes {
        assert_eq!(route.method, "GET", "{}", route.path);
    }
    assert_eq!(finding_paths(&report), ["/admin/c"]);
}

#[test]
fn role_comparisons_in_handler_bodies_are_evidence() {
    let report = fixture_report(
        "e7-role-comparisons",
        include_str!("../../tests/fixtures/probes/e7_role_comparisons.rs"),
    );
    for path in ["/admin/a", "/admin/b", "/admin/c", "/admin/d"] {
        assert_eq!(
            route_at(&report, path).best_tier(),
            EvidenceTier::Privilege,
            "{path}"
        );
    }
    assert_eq!(finding_paths(&report), ["/admin/e"]);
}

#[test]
fn comparisons_with_non_authorization_values_are_not_evidence() {
    let report = fixture_report(
        "e7-non-role-comparisons",
        "async fn a(order: Order) { if order.status != Status::Paid { return; } }
         async fn b(user: User) { if user.name == \"admin\" { return; } }
         async fn c(user: User) { let _ = user.roles.len() == 2; set_role(Role::Admin); }
         fn main() { App::new().route(\"/a\", web::get().to(a)).route(\"/b\", web::get().to(b)).route(\"/c\", web::get().to(c)); }",
    );
    for route in &report.routes {
        assert!(
            route.authorization.is_empty(),
            "{}: {:?}",
            route.path,
            route.authorization
        );
    }
}

#[test]
fn authorization_in_called_helpers_is_evidence_for_the_handler() {
    let report = fixture_report(
        "e8-helper-wrapper",
        include_str!("../../tests/fixtures/probes/e8_helper_wrapper.rs"),
    );
    let route = route_at(&report, "/admin/a");
    assert!(has_evidence(
        route,
        AuthEvidenceKind::RoleCheck,
        "require_admin"
    ));
    assert!(report.finding_details.is_empty());
}

#[test]
fn recursive_helpers_do_not_loop() {
    let report = fixture_report(
        "e8-recursive-helpers",
        "fn ping(n: u32) { pong(n) }
         fn pong(n: u32) { ping(n); require_admin(); }
         async fn h() { ping(1); }
         fn main() { App::new().route(\"/h\", web::get().to(h)); }",
    );
    assert!(has_evidence(
        route_at(&report, "/h"),
        AuthEvidenceKind::RoleCheck,
        "require_admin"
    ));
}

#[test]
fn large_peer_groups_are_grouped_without_pairwise_comparison() {
    let routes: String = (0..10_000)
        .map(|index| format!("\n    cfg.route(\"/x/r{index}\", web::get().to(h));"))
        .collect();
    let report = fixture_report(
        "e1-large-group",
        &format!(
            "async fn h() {{}}\nasync fn admin(_u: AdminUser) {{}}\n\
             fn config(cfg: &mut ServiceConfig) {{\n    cfg.route(\"/x/a\", web::get().to(admin));\n    cfg.route(\"/x/b\", web::get().to(admin));{routes}\n}}"
        ),
    );
    assert_eq!(report.routes.len(), 10_002);
    assert_eq!(report.peer_groups.len(), 1);
    assert!(
        report.finding_details.is_empty(),
        "2 of 10002 is not dominant"
    );
}

#[test]
fn a_route_factory_called_in_two_scopes_registers_in_both() {
    let report = fixture_report(
        "e4-two-scopes",
        "fn users() -> Scope { web::scope(\"/users\").route(\"\", web::get().to(h)) }
         fn helper(n: u32) -> u32 { n }
         async fn h() {}
         fn main() {
             helper(1);
             App::new()
                 .service(web::scope(\"/v1\").service(users()))
                 .service(web::scope(\"/v2\").wrap(RequireAdminMiddleware).service(users()));
         }",
    );
    // Both expansions share the factory's source position.
    let mut paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    paths.sort();
    assert_eq!(paths, ["/v1/users", "/v2/users"]);
    assert!(route_at(&report, "/v1/users").authorization.is_empty());
    assert!(has_evidence(
        route_at(&report, "/v2/users"),
        AuthEvidenceKind::AuthorizationMiddleware,
        "RequireAdminMiddleware"
    ));
}

#[test]
fn config_functions_reachable_only_from_themselves_keep_their_routes() {
    let report = fixture_report(
        "e9-self-configure",
        "fn a(cfg: &mut ServiceConfig) { cfg.route(\"/a\", web::get().to(h)); b(cfg); }
         fn b(cfg: &mut ServiceConfig) { cfg.route(\"/b\", web::get().to(h)).configure(a); }
         fn c(cfg: &mut ServiceConfig) { cfg.route(\"/c\", web::get().to(h)); c(cfg); }
         async fn h() {}",
    );
    let mut paths: Vec<_> = report
        .routes
        .iter()
        .map(|route| route.path.as_str())
        .collect();
    paths.sort();
    paths.dedup();
    assert_eq!(paths, ["/a", "/b", "/c"]);
}

// Drift-detection regression fixtures: each one pins a class of drift that
// Archer must report, or a design it must not report as drift.

fn drift_fixture(name: &str, source: &str) -> Report {
    TempRepo::new(name, &[("main.rs", source)]).analyze()
}

/// `(category, method, path)` of each finding, sorted.
fn reported(report: &Report) -> Vec<(FindingCategory, String, String)> {
    let mut reported: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| {
            (
                finding.category,
                finding.suspicious_route.method.clone(),
                finding.suspicious_route.path.clone(),
            )
        })
        .collect();
    reported.sort_by(|a, b| (&a.1, &a.2).cmp(&(&b.1, &b.2)));
    reported
}

fn finding(
    category: FindingCategory,
    method: &str,
    path: &str,
) -> (FindingCategory, String, String) {
    (category, method.into(), path.into())
}

use FindingCategory::*;

#[test]
fn f01_a_write_missing_the_guard_its_resource_writes_have_is_reported() {
    let report = drift_fixture(
        "f01",
        include_str!("../../tests/fixtures/probes/drift/f01_crud_write_missing_guard.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "DELETE", "/admin/users/{id}")]
    );
    assert_eq!(report.finding_details[0].severity, Severity::High);
    assert_eq!(report.finding_details[0].authorized_peer_routes.len(), 2);
}

#[test]
fn f02_a_public_route_among_authenticated_peers_is_missing_authentication() {
    let report = drift_fixture(
        "f02",
        include_str!("../../tests/fixtures/probes/drift/f02_missing_authentication.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthentication, "GET", "/api/exports")]
    );
    assert_eq!(
        report.finding_details[0].expected_tier,
        EvidenceTier::Identity
    );
}

#[test]
fn f03_a_route_checking_a_different_role_than_its_peers_is_reported() {
    let report = drift_fixture(
        "f03",
        include_str!("../../tests/fixtures/probes/drift/f03_different_role.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(DifferentAuthorization, "GET", "/admin/secrets")]
    );
    assert_eq!(
        report.invariants[0].dominant_requirement.as_deref(),
        Some("admin")
    );
    assert!(report.finding_details[0].rationale.contains("`viewer`"));
}

#[test]
fn f04_checks_that_only_feed_display_or_logging_are_not_protection() {
    let report = drift_fixture(
        "f04",
        include_str!("../../tests/fixtures/probes/drift/f04_mentions_are_not_checks.rs"),
    );
    for path in ["/admin/secrets", "/admin/reports", "/admin/exports"] {
        assert!(route_at(&report, path).authorization.is_empty(), "{path}");
    }
    assert_eq!(
        reported(&report),
        [
            finding(MissingAuthorization, "GET", "/admin/exports"),
            finding(MissingAuthorization, "GET", "/admin/reports"),
            finding(MissingAuthorization, "GET", "/admin/secrets"),
        ]
    );
}

#[test]
fn f05_builders_held_in_variables_keep_their_prefix_guards_and_routes() {
    let report = drift_fixture(
        "f05",
        include_str!("../../tests/fixtures/probes/drift/f05_builders_in_variables.rs"),
    );
    assert!(has_evidence(
        route_at(&report, "/admin/users"),
        AuthEvidenceKind::AuthorizationMiddleware,
        "AdminGuard"
    ));
    assert!(has_evidence(
        route_at(&report, "/ops/a"),
        AuthEvidenceKind::AuthorizationGuard,
        "AdminGuard"
    ));
    assert_eq!(route_at(&report, "/admin/users").scope_prefix, "/admin");
    route_at(&report, "/orphan/x");
    // `/orphan/x` registers handler `a`, which `/ops/a` registers behind
    // `AdminGuard`.
    assert_eq!(
        reported(&report),
        [
            finding(MissingAuthorization, "GET", "/ops/d"),
            finding(InconsistentRegistration, "GET", "/orphan/x"),
        ]
    );
}

#[test]
fn f06_closure_handlers_are_analysed_in_place() {
    let report = drift_fixture(
        "f06",
        include_str!("../../tests/fixtures/probes/drift/f06_closure_handlers.rs"),
    );
    let stats = route_at(&report, "/admin/stats");
    assert_eq!(stats.handler_resolution, Some(HandlerResolution::Closure));
    assert!(has_evidence(
        stats,
        AuthEvidenceKind::RoleCheck,
        "AdminUser"
    ));
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "GET", "/admin/debug")]
    );
}

#[test]
fn f07_unrecognized_middleware_makes_a_gap_unverified_unless_peers_share_it() {
    let report = drift_fixture(
        "f07",
        include_str!("../../tests/fixtures/probes/drift/f07_unrecognized_middleware.rs"),
    );
    assert!(has_evidence(
        route_at(&report, "/admin/stats"),
        AuthEvidenceKind::Unknown,
        "StaffOnlyGate"
    ));
    // `Logger` is infrastructure, not unknown.
    assert!(
        !route_at(&report, "/admin/users")
            .authorization
            .iter()
            .any(|evidence| evidence.kind == AuthEvidenceKind::Unknown)
    );
    assert_eq!(
        reported(&report),
        [
            finding(UnverifiedProtection, "GET", "/admin/stats"),
            finding(MissingAuthorization, "GET", "/team/stats"),
        ]
    );
    let unverified = &report.finding_details[0];
    assert_eq!(unverified.severity, Severity::Low);
}

#[test]
fn f08_enforced_checks_count_in_every_common_form() {
    let report = drift_fixture(
        "f08",
        include_str!("../../tests/fixtures/probes/drift/f08_enforcement_forms.rs"),
    );
    for route in &report.routes {
        assert_eq!(route.best_tier(), EvidenceTier::Privilege, "{}", route.path);
        assert_eq!(route.privilege_requirements(), ["admin"], "{}", route.path);
    }
    assert!(report.finding_details.is_empty());
}

#[test]
fn f09_ownership_comparisons_queries_and_filters_are_resource_evidence() {
    let report = drift_fixture(
        "f09",
        include_str!("../../tests/fixtures/probes/drift/f09_ownership.rs"),
    );
    for method in ["GET", "PUT", "DELETE"] {
        let route = report
            .routes
            .iter()
            .find(|route| route.method == method)
            .unwrap();
        assert_eq!(route.best_tier(), EvidenceTier::Resource, "{method}");
    }
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "PATCH", "/api/posts/{id}")]
    );
    assert_eq!(report.finding_details[0].severity, Severity::Medium);
}

#[test]
fn f10_public_reads_are_not_drift_but_writes_below_their_reads_are() {
    let report = drift_fixture(
        "f10",
        include_str!("../../tests/fixtures/probes/drift/f10_public_reads_protected_writes.rs"),
    );
    assert_eq!(
        reported(&report),
        [
            finding(MissingAuthorization, "DELETE", "/blog/posts/{id}"),
            finding(MissingAuthorization, "PUT", "/admin/settings/{key}"),
        ]
    );
}

#[test]
fn f11_a_consistently_public_resource_is_not_drift_but_a_lone_one_is() {
    let report = drift_fixture(
        "f11",
        include_str!("../../tests/fixtures/probes/drift/f11_public_resource_by_design.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthentication, "GET", "/portal/exports")]
    );
}

#[test]
fn f12_exemptions_cover_only_generic_auth_and_health_endpoints() {
    let report = drift_fixture(
        "f12",
        include_str!("../../tests/fixtures/probes/drift/f12_exemptions.rs"),
    );
    assert_eq!(
        reported(&report),
        [
            finding(MissingAuthorization, "GET", "/admin/metrics"),
            finding(MissingAuthorization, "GET", "/admin/settings/auth"),
        ]
    );
}

#[test]
fn f13_identity_and_logging_middleware_neither_protect_nor_hide_drift() {
    let report = drift_fixture(
        "f13",
        include_str!("../../tests/fixtures/probes/drift/f13_infrastructure_middleware.rs"),
    );
    assert!(report.routes.iter().all(|route| {
        route
            .authorization
            .iter()
            .all(|evidence| evidence.kind != AuthEvidenceKind::Unknown)
    }));
    assert_eq!(
        reported(&report),
        [finding(MissingAuthentication, "GET", "/me/exports")]
    );
}

#[test]
fn f14_requirements_compare_across_mechanisms_but_not_per_route_permissions() {
    let report = drift_fixture(
        "f14",
        include_str!("../../tests/fixtures/probes/drift/f14_requirement_keys.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(DifferentAuthorization, "GET", "/staff/d")]
    );
}

#[test]
fn f15_unresolved_and_opaque_handlers_are_unverified_not_missing() {
    let report = drift_fixture(
        "f15",
        include_str!("../../tests/fixtures/probes/drift/f15_unresolved_handler.rs"),
    );
    assert_eq!(
        reported(&report),
        [
            finding(UnverifiedProtection, "GET", "/admin/plugins"),
            finding(UnverifiedProtection, "GET", "/admin/stats"),
        ]
    );
}

#[test]
fn f16_wrap_fn_closures_are_unknown_and_routing_guards_are_ignored() {
    let report = drift_fixture(
        "f16",
        include_str!("../../tests/fixtures/probes/drift/f16_wrap_fn_and_guards.rs"),
    );
    assert_eq!(
        reported(&report),
        [
            finding(UnverifiedProtection, "GET", "/admin/hook"),
            finding(MissingAuthorization, "GET", "/admin/json"),
        ]
    );
}

#[test]
fn sql_literals_scope_to_the_caller_only_with_a_bound_owner_column() {
    assert!(sql_scopes_to_caller(
        "SELECT * FROM posts WHERE id = $1 AND owner_id = $2"
    ));
    assert!(sql_scopes_to_caller("delete from notes where user_id=?"));
    assert!(!sql_scopes_to_caller(
        "SELECT owner_id FROM posts WHERE id = $1"
    ));
    assert!(!sql_scopes_to_caller(
        "SELECT * FROM posts WHERE co_owner_id = $1"
    ));
    assert!(!sql_scopes_to_caller("UPDATE posts SET user_id = $1"));
}

#[test]
fn requirement_keys_normalize_names_literals_and_variants() {
    assert_eq!(name_keys("require_admin"), ["admin"]);
    assert_eq!(name_keys("AdminUser"), ["admin"]);
    assert_eq!(name_keys("AdminGuard"), ["admin"]);
    assert_eq!(name_keys("check_billing_admin"), ["billing_admin"]);
    assert!(name_keys("check_role").is_empty());
    assert!(name_keys("authorize").is_empty());
    assert_eq!(normalize_key("ROLE_ADMIN").as_deref(), Some("admin"));
    assert_eq!(normalize_key("Administrators").as_deref(), Some("admin"));
    assert_eq!(literal_key("reports:read").as_deref(), Some("reports:read"));
    assert!(literal_key("you are not allowed").is_none());
    let expr: syn::Expr = syn::parse_str("user.roles.contains(&UserRole::SuperUser)").unwrap();
    assert_eq!(keys_in_expr(&expr), ["super_user"]);
}

#[test]
fn placement_uses_the_scope_then_generic_prefixes_then_the_first_segment() {
    let place = |method: &str, path: &str, scope: &str| {
        let placed = placement(&route(method, path, scope, "NONE"));
        (placed.namespace, placed.resource, placed.class)
    };
    assert_eq!(
        place("GET", "/admin/users/{id}/roles", "/admin"),
        ("/admin".into(), "/admin/users".into(), MethodClass::Read)
    );
    assert_eq!(
        place("DELETE", "/api/v1/orders/{id}", ""),
        (
            "/api/v1".into(),
            "/api/v1/orders".into(),
            MethodClass::Write
        )
    );
    assert_eq!(
        place("GET", "/admin/users", ""),
        ("/admin".into(), "/admin/users".into(), MethodClass::Read)
    );
    assert_eq!(
        place("GET", "/t/{tenant}/users", "/t/{tenant}"),
        ("/t/{}".into(), "/t/{}/users".into(), MethodClass::Read)
    );
    assert_eq!(MethodClass::of("UNKNOWN"), MethodClass::Write);
    assert_eq!(MethodClass::of("HEAD"), MethodClass::Read);
}

#[test]
fn exemptions_require_a_generic_or_account_context() {
    let exempt = |path: &str| {
        let route = route("GET", path, "", "NONE");
        (
            is_authentication_route(&route),
            is_well_known_public_route(&route),
        )
    };
    assert_eq!(exempt("/api/v1/auth/login"), (true, false));
    assert_eq!(exempt("/users/password/reset"), (true, false));
    assert_eq!(exempt("/admin/users/{id}/token"), (false, false));
    assert_eq!(exempt("/healthz"), (false, true));
    assert_eq!(exempt("/api/openapi.json"), (false, true));
    assert_eq!(exempt("/admin/metrics"), (false, false));
    assert_eq!(exempt("/orders/{id}/status"), (false, false));
}

#[test]
fn bool_helpers_lend_their_predicate_only_where_the_caller_enforces_it() {
    let report = fixture_report(
        "predicate-helpers",
        "fn can_manage(u: &User) -> bool { u.role == Role::Admin || is_superuser(u) }
         fn is_superuser(u: &User) -> bool { u.flags.superuser }
         async fn enforced(u: User) -> Resp { if !can_manage(&u) { return forbidden(); } ok() }
         async fn ignored(u: User) -> Resp { let label = if can_manage(&u) { \"a\" } else { \"b\" }; ok() }
         async fn tried(u: User) -> Result<(), E> { ensure_admin(&u)?; Ok(()) }
         fn ensure_admin(u: &User) -> Result<(), E> { if u.role != Role::Admin { return Err(E::Forbidden); } Ok(()) }
         fn config(cfg: &mut ServiceConfig) {
             cfg.route(\"/x/enforced\", web::get().to(enforced))
                .route(\"/x/ignored\", web::get().to(ignored))
                .route(\"/x/tried\", web::get().to(tried));
         }",
    );
    assert!(route_at(&report, "/x/enforced").is_authorized());
    assert!(!route_at(&report, "/x/ignored").is_authorized());
    assert!(route_at(&report, "/x/tried").is_authorized());
}

#[test]
fn text_findings_name_category_severity_and_reason() {
    let report = drift_fixture(
        "text-findings",
        include_str!("../../tests/fixtures/probes/drift/f02_missing_authentication.rs"),
    );
    let text = &report.findings[0];
    assert!(
        text.contains("Category: missing authentication (severity high"),
        "{text}"
    );
    assert!(text.contains("Why: No authentication"), "{text}");
}

#[test]
fn f17_auth_named_middleware_authenticates_unless_conditional() {
    let report = drift_fixture(
        "f17",
        include_str!("../../tests/fixtures/probes/drift/f17_auth_named_middleware.rs"),
    );
    assert!(has_evidence(
        route_at(&report, "/admin/logout"),
        AuthEvidenceKind::IdentityExtraction,
        "reject_anonymous_users"
    ));
    assert!(has_evidence(
        route_at(&report, "/internal/stats"),
        AuthEvidenceKind::Unknown,
        "ApiKeyAuth"
    ));
    assert_eq!(reported(&report), []);
}

#[test]
fn f18_identity_handed_to_unanalyzed_code_is_unverified_not_missing() {
    let report = drift_fixture(
        "f18",
        include_str!("../../tests/fixtures/probes/drift/f18_delegated_identity.rs"),
    );
    assert!(
        route_at(&report, "/collections/d")
            .authorization
            .iter()
            .any(|evidence| evidence.kind == AuthEvidenceKind::Delegated)
    );
    assert_eq!(
        reported(&report),
        [
            finding(UnverifiedProtection, "POST", "/collections/d"),
            finding(MissingAuthorization, "POST", "/collections/e"),
        ]
    );
}

#[test]
fn f19_one_handler_registered_with_and_without_a_scope_layer() {
    let report = drift_fixture(
        "f19",
        include_str!("../../tests/fixtures/probes/drift/f19_duplicate_registration.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(InconsistentRegistration, "POST", "/newsletters")]
    );
    let detail = &report.finding_details[0];
    assert_eq!(detail.severity, Severity::High);
    assert!(detail.rationale.contains("/admin/newsletters"));
}

#[test]
fn f20_lone_read_in_a_nested_scope_is_compared_with_the_enclosing_scope() {
    let report = drift_fixture(
        "f20",
        include_str!("../../tests/fixtures/probes/drift/f20_scope_tree_fallback.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "GET", "/admin/tagline/list")]
    );
}

#[test]
fn f21_helper_parameter_types_and_creates_are_not_drift() {
    let report = drift_fixture(
        "f21",
        include_str!("../../tests/fixtures/probes/drift/f21_helper_types_and_creates.rs"),
    );
    assert!(
        route_at(&report, "/ogc/map/tiles/{id}")
            .authorization
            .iter()
            .all(|evidence| evidence.kind != AuthEvidenceKind::RoleCheck)
    );
    assert_eq!(reported(&report), []);
}

#[test]
fn f22_test_modules_are_not_scanned_and_coverage_is_reported() {
    let report = drift_fixture(
        "f22",
        include_str!("../../tests/fixtures/probes/drift/f22_test_modules_and_coverage.rs"),
    );
    let paths: Vec<_> = report.routes.iter().map(|route| route.path.as_str()).collect();
    assert_eq!(paths, ["/"]);
    assert_eq!(report.coverage.likely_handlers, 2);
    assert_eq!(report.coverage.routed_handlers, 1);
    assert!(report.coverage.unrouted_examples[0].ends_with("orphaned"));
}

#[test]
fn handlers_resolve_into_other_workspace_crates() {
    let repo = TempRepo::new(
        "cross-crate",
        &[
            ("Cargo.toml", "[workspace]\nmembers = [\"routes\", \"api\"]\n"),
            ("routes/Cargo.toml", "[package]\nname = \"app-routes\"\n"),
            (
                "routes/src/lib.rs",
                "use actix_web::web;
                 use app_api::admin::{ban, purge};
                 pub fn config(cfg: &mut web::ServiceConfig) {
                     cfg.service(web::scope(\"/admin\")
                         .route(\"/ban\", web::post().to(ban))
                         .route(\"/purge\", web::post().to(purge))
                         .route(\"/list\", web::post().to(app_api::admin::list)));
                 }",
            ),
            ("api/Cargo.toml", "[package]\nname = \"app-api\"\n"),
            ("api/src/lib.rs", "pub mod admin;"),
            (
                "api/src/admin.rs",
                "pub async fn ban(u: LocalUserView) { is_admin(&u)?; }
                 pub async fn purge(u: LocalUserView) { is_admin(&u)?; }
                 pub async fn list(u: LocalUserView) {}",
            ),
        ],
    );
    let report = repo.analyze();
    for path in ["/admin/ban", "/admin/purge"] {
        let route = route_at(&report, path);
        assert_eq!(resolution(route), &HandlerResolution::Imported, "{path}");
        assert!(has_evidence(route, AuthEvidenceKind::RoleCheck, "is_admin"), "{path}");
    }
    assert_eq!(
        resolution(route_at(&report, "/admin/list")),
        &HandlerResolution::Qualified
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "POST", "/admin/list")]
    );
}

#[test]
fn library_names_come_from_lib_then_package() {
    use super::library_name;
    assert_eq!(
        library_name("[package]\nname = \"lemmy-api\"\n").as_deref(),
        Some("lemmy_api")
    );
    assert_eq!(
        library_name("[package]\nname = \"x\"\n[lib]\nname = \"y_lib\"\n").as_deref(),
        Some("y_lib")
    );
    assert_eq!(library_name("[workspace]\nmembers = []\n"), None);
}

#[test]
fn credential_checks_identify_the_caller() {
    assert_eq!(
        classify_check_name("validate_secret").map(|(kind, _)| kind),
        Some(AuthEvidenceKind::IdentityExtraction)
    );
    assert_eq!(classify_check_name("validate_reset_token"), None);
}

#[test]
fn f23_named_authorization_layers_and_resource_method_guards() {
    let report = drift_fixture(
        "f23",
        include_str!(
            "../../tests/fixtures/probes/drift/f23_named_authorization_and_resource_guards.rs"
        ),
    );
    assert!(has_evidence(
        route_at(&report, "/coordinate/b"),
        AuthEvidenceKind::AuthorizationMiddleware,
        "coordinator_authorization_middleware"
    ));
    assert_eq!(route_at(&report, "/form/{id}").method, "GET");
    assert_eq!(reported(&report), []);
}

#[test]
fn files_of_test_only_modules_are_not_scanned() {
    let repo = TempRepo::new(
        "test-module-file",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/lib.rs",
                "#[cfg(test)]\nmod tests;\npub fn config(cfg: &mut web::ServiceConfig) { cfg.route(\"/a\", web::get().to(a)); }\nasync fn a() {}",
            ),
            (
                "src/tests.rs",
                "fn app() { App::new().configure(crate::config).route(\"/fixture\", web::get().to(crate::a)); }",
            ),
        ],
    );
    let paths: Vec<_> = repo.analyze().routes.into_iter().map(|route| route.path).collect();
    assert_eq!(paths, ["/a"]);
}

#[test]
fn f24_validate_methods_on_the_caller_are_role_checks() {
    let report = drift_fixture(
        "f24",
        include_str!("../../tests/fixtures/probes/drift/f24_validate_methods.rs"),
    );
    let list = route_at(&report, "/api/users");
    assert!(has_evidence(list, AuthEvidenceKind::RoleCheck, "validate_admin_session"));
    assert!(
        list.authorization
            .iter()
            .any(|evidence| evidence.requirements == ["admin"])
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "DELETE", "/api/users/{id}/sessions")]
    );
}

#[test]
fn f25_a_resource_that_disagrees_is_judged_by_its_namespace() {
    let report = drift_fixture(
        "f25",
        include_str!("../../tests/fixtures/probes/drift/f25_undecided_resource.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthentication, "POST", "/api/post/mark_as_read/many")]
    );
}

#[test]
fn f26_only_record_writes_are_held_to_the_resource_reads() {
    let report = drift_fixture(
        "f26",
        include_str!("../../tests/fixtures/probes/drift/f26_record_writes_and_sub_actions.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "PUT", "/api/accounts/{id}")]
    );
}

#[test]
fn unregistered_attribute_routes_are_left_out_with_a_warning() {
    let report = drift_fixture(
        "f27",
        include_str!("../../tests/fixtures/probes/drift/f27_unregistered_and_macro_routes.rs"),
    );
    let paths: Vec<_> = report.routes.iter().map(|route| route.path.as_str()).collect();
    assert_eq!(paths, ["/articles/{id}", "/articles"]);
    assert_eq!(report.coverage.unregistered_attribute_routes, 1);
    assert_eq!(report.coverage.macro_registrations, [("api_routes".to_string(), 2)]);
    assert!(report.warnings.iter().any(|warning| warning.contains("never registered")));
    assert_eq!(reported(&report), []);
}

#[test]
fn middleware_that_checks_only_some_paths_is_unverified() {
    let report = drift_fixture(
        "f28",
        include_str!("../../tests/fixtures/probes/drift/f28_path_conditional_middleware.rs"),
    );
    let kinds = |path: &str| -> Vec<AuthEvidenceKind> {
        report
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("no route {path}"))
            .authorization
            .iter()
            .map(|evidence| evidence.kind.clone())
            .collect()
    };
    // Evaluated and unconditional: authentication, as before.
    assert_eq!(kinds("/members/profile"), [AuthEvidenceKind::IdentityExtraction]);
    // A literal path test is settled per route: `path.contains("/private")`
    // protects the private routes and leaves `/portal/shared/drafts` out.
    assert_eq!(kinds("/portal/private/drafts"), [AuthEvidenceKind::IdentityExtraction]);
    assert!(kinds("/portal/shared/drafts").is_empty());
    // `path != "/api/login"` exempts the login route and checks the rest.
    assert!(kinds("/api/login").is_empty());
    assert_eq!(kinds("/api/orders"), [AuthEvidenceKind::IdentityExtraction]);
    assert_eq!(kinds("/api/orders/{id}"), [AuthEvidenceKind::IdentityExtraction]);
    // Tests Archer cannot settle (a helper, a guarded match arm, a closure)
    // stay unverified: not counted as protection.
    assert_eq!(kinds("/board/posts"), [AuthEvidenceKind::Delegated]);
    assert_eq!(kinds("/desk/tickets"), [AuthEvidenceKind::Delegated]);
    assert_eq!(kinds("/inbox/messages"), [AuthEvidenceKind::Delegated]);
    // The shared draft route is the one its `/portal` peers' middleware
    // does not cover.
    assert_eq!(
        reported(&report),
        [(
            FindingCategory::InconsistentRegistration,
            "GET".to_string(),
            "/portal/shared/drafts".to_string()
        )]
    );
}

#[test]
fn role_lists_and_ownership_are_compared_as_fields() {
    let report = drift_fixture(
        "f29",
        include_str!("../../tests/fixtures/probes/drift/f29_role_lists_and_ownership.rs"),
    );
    let requirement = |method: &str, path: &str| -> Requirement {
        report
            .routes
            .iter()
            .find(|route| route.method == method && route.path == path)
            .unwrap_or_else(|| panic!("no route {method} {path}"))
            .requirement
            .clone()
    };
    let daily = requirement("GET", "/reports/daily");
    assert_eq!(daily.roles, ["admin"]);
    assert!(daily.authenticated && !daily.roles_any_of);
    let yearly = requirement("GET", "/reports/yearly");
    assert_eq!(yearly.roles, ["admin", "viewer"]);
    assert!(yearly.roles_any_of);
    assert!(requirement("PUT", "/notes/{id}").ownership);
    assert!(requirement("PATCH", "/notes/{id}").ownership);
    assert!(!requirement("DELETE", "/notes/{id}").ownership);
    assert_eq!(
        reported(&report),
        [
            (FindingCategory::MissingAuthorization, "DELETE".to_string(), "/notes/{id}".to_string()),
            (FindingCategory::WeakerAuthorization, "GET".to_string(), "/reports/yearly".to_string()),
        ]
    );
}

#[test]
fn routes_serving_the_same_data_are_compared_across_paths() {
    let report = drift_fixture(
        "f30",
        include_str!("../../tests/fixtures/probes/drift/f30_same_resource_links.rs"),
    );
    let keys = |path: &str| -> Vec<String> {
        report
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("no route {path}"))
            .resource_keys
            .clone()
    };
    assert!(keys("/catalog/item/{id}/{rev}").contains(&"calls crate::store::load_revision".to_string()));
    assert!(keys("/studio/item/{id}").contains(&"calls crate::store::load_item".to_string()));
    // One shared error constructor is not a resource link.
    assert!(keys("/catalog/item/{id}").contains(&"calls crate::store::not_found".to_string()));
    assert_eq!(
        reported(&report),
        [(
            FindingCategory::SameResourceWeakerProtection,
            "GET".to_string(),
            "/catalog/item/{id}/{rev}".to_string()
        )]
    );
    let finding = &report.finding_details[0];
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.authorized_peer_routes[0].path, "/studio/item/{id}");
}

#[test]
fn small_groups_fall_back_to_enclosing_scopes_and_unjudged_routes_say_why() {
    let report = drift_fixture(
        "f31",
        include_str!("../../tests/fixtures/probes/drift/f31_small_group_fallback.rs"),
    );
    assert_eq!(
        reported(&report),
        [(FindingCategory::MissingAuthentication, "POST".to_string(), "/shop/cart/clear".to_string())]
    );
    let reason = |path: &str| {
        report
            .unjudged
            .iter()
            .find(|route| route.path == path)
            .map(|route| route.reason)
    };
    assert_eq!(reason("/misc/about"), Some(UnjudgedReason::NoPeers));
    // The detail names the levels tried and the app-wide pattern.
    let about = report.unjudged.iter().find(|route| route.path == "/misc/about").unwrap();
    assert!(about.detail.contains("resource /misc/about"), "{}", about.detail);
    assert!(about.detail.contains("the whole app"), "{}", about.detail);
    // An unprotected group is formed (tier None) and judges its routes.
    assert_eq!(reason("/blog/posts"), None);
    let blog = report
        .peer_groups
        .iter()
        .find(|group| group.routes.iter().any(|route| route.path == "/blog/posts"))
        .unwrap();
    assert!(blog.description.contains("tier None"), "{}", blog.description);
    // Judged routes are not listed.
    assert_eq!(reason("/shop/orders/place"), None);
    assert_eq!(reason("/shop/cart/clear"), None);
    assert!(report.warnings.iter().any(|warning| warning.contains("not compared with any peers")));
}

#[test]
fn attribute_routes_registered_through_a_glob_imported_module_are_kept() {
    let repo = TempRepo::new(
        "glob-registration",
        &[
            ("Cargo.toml", CARGO_TOML),
            ("src/main.rs", "mod api;\nmod config;\n"),
            ("src/api/mod.rs", "pub mod ping_controller;\n"),
            (
                "src/api/ping_controller.rs",
                "#[get(\"/ping\")]\nasync fn ping() -> HttpResponse { HttpResponse::Ok().finish() }\n",
            ),
            ("src/config/mod.rs", "pub mod app;\n"),
            (
                "src/config/app.rs",
                "use crate::api::*;\npub fn config(cfg: &mut web::ServiceConfig) {\n    cfg.service(web::scope(\"/api\").service(ping_controller::ping));\n}\n",
            ),
        ],
    );
    let report = repo.analyze();
    let paths: Vec<_> = report.routes.iter().map(|route| route.path.as_str()).collect();
    assert_eq!(paths, ["/api/ping"]);
    assert_eq!(report.coverage.unregistered_attribute_routes, 0);
}

#[test]
fn routes_under_a_runtime_mount_prefix_are_still_compared() {
    let report = drift_fixture(
        "f32",
        include_str!("../../tests/fixtures/probes/drift/f32_runtime_mount_prefix.rs"),
    );
    assert!(report.routes.iter().any(|route| route.path == "/<unresolved:cfg.base_uri>/api/projects"));
    assert_eq!(
        reported(&report),
        [(
            FindingCategory::MissingAuthentication,
            "DELETE".to_string(),
            "/<unresolved:cfg.base_uri>/api/projects/{id}".to_string()
        )]
    );
    assert!(report.unjudged.iter().any(|route| {
        route.path.contains("export") && route.reason == UnjudgedReason::UnresolvedPath
    }));
    // A health check under the prefix is still a well-known public endpoint.
    assert!(report.unjudged.iter().any(|route| {
        route.path.ends_with("/healthz") && route.reason == UnjudgedReason::WellKnownPublic
    }));
}

#[test]
fn routes_that_skip_the_check_their_peers_make_with_the_caller_are_reported() {
    let report = drift_fixture(
        "f33",
        include_str!("../../tests/fixtures/probes/drift/f33_peer_checks.rs"),
    );
    let skipped: Vec<_> = reported(&report)
        .into_iter()
        .filter(|(category, _, _)| *category == FindingCategory::SkipsPeerCheck)
        .map(|(_, method, path)| format!("{method} {path}"))
        .collect();
    assert_eq!(skipped, ["DELETE /billing/evidence", "GET /forum/multi"]);
    let multi = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/forum/multi")
        .unwrap();
    assert_eq!(multi.severity, Severity::Medium);
    assert!(multi.rationale.contains("4 of 5 under /forum check the caller with `check_private_instance`"), "{}", multi.rationale);
    assert_eq!(multi.authorized_peer_routes.len(), 4);
    // The check made in the service function counts for the handler.
    let attach = report.routes.iter().find(|route| route.method == "PUT").unwrap();
    assert!(attach.caller_use.contains(&"checks:AuthData:validate_profile".to_string()), "{:?}", attach.caller_use);
    // The forwarding closure resolves to `update_evidence`.
    let patch = report.routes.iter().find(|route| route.method == "PATCH").unwrap();
    assert_eq!(patch.handler.as_deref(), Some("update_evidence"));
}

#[test]
fn peer_checks_use_verdict_calls_version_groups_and_open_schemes() {
    let report = drift_fixture(
        "f34",
        include_str!("../../tests/fixtures/probes/drift/f34_verdicts_versions_schemes.rs"),
    );
    let skipped: Vec<_> = report
        .finding_details
        .iter()
        .filter(|finding| finding.category == FindingCategory::SkipsPeerCheck)
        .map(|finding| {
            (
                format!("{} {}", finding.suspicious_route.method, finding.suspicious_route.path),
                finding.severity,
            )
        })
        .collect();
    assert_eq!(
        skipped,
        [
            ("GET /api/v2/multi".to_string(), Severity::Medium),
            ("POST /reports/export".to_string(), Severity::Medium),
            ("POST /reports/schema".to_string(), Severity::Low),
        ],
        "{:#?}",
        report.finding_details.iter().map(|finding| &finding.rationale).collect::<Vec<_>>()
    );
    let multi = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/api/v2/multi")
        .unwrap();
    assert!(multi.rationale.contains("6 of 6 under /api/v2"), "{}", multi.rationale);
    // A call that returns data is not a check, even with `?`.
    let bio = report.routes.iter().find(|route| route.path == "/profile/bio").unwrap();
    assert!(!bio.caller_use.iter().any(|feature| feature.starts_with("checks:")), "{:?}", bio.caller_use);
    assert!(bio.caller_use.contains(&"acts:LocalUserView".to_string()));
}

#[test]
fn a_route_that_discards_the_caller_its_peers_get_from_a_call_is_reported() {
    let report = drift_fixture(
        "f35",
        include_str!("../../tests/fixtures/probes/drift/f35_caller_from_call.rs"),
    );
    let update = report.routes.iter().find(|route| route.method == "PATCH").unwrap();
    assert!(update.caller_use.contains(&"takes:authorize_session()".to_string()), "{:?}", update.caller_use);
    let skipped: Vec<_> = report
        .finding_details
        .iter()
        .filter(|finding| finding.category == FindingCategory::SkipsPeerCheck)
        .map(|finding| (finding.suspicious_route.path.clone(), finding.severity))
        .collect();
    assert_eq!(
        skipped,
        [("/profile/license".to_string(), Severity::Medium)],
        "{:#?}",
        report.finding_details.iter().map(|finding| &finding.rationale).collect::<Vec<_>>()
    );
}

#[test]
fn routes_declared_in_mounted_route_tables_are_analyzed() {
    let report = drift_fixture(
        "f36",
        include_str!("../../tests/fixtures/probes/drift/f36_route_tables.rs"),
    );
    let mut paths: Vec<String> = report
        .routes
        .iter()
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            "DELETE /api/indexes/{uid}",
            "DELETE /api/keys/{key}",
            "GET /api/health",
            "GET /api/indexes",
            "GET /api/indexes/{uid}",
            "GET /api/indexes/{uid}/stats",
            "GET /api/keys",
            "GET /api/keys/{key}",
            "PATCH /api/keys/{key}",
            "POST /api/indexes",
            "POST /api/keys",
        ]
    );
    let list = report.routes.iter().find(|route| route.path == "/api/keys" && route.method == "GET").unwrap();
    assert_eq!(list.requirement.roles, ["keys_get"]);
    assert!(report.warnings.iter().any(|warning| warning.contains("CompactApi")), "{:?}", report.warnings);
    let found: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| (finding.suspicious_route.method.clone(), finding.suspicious_route.path.clone(), finding.severity))
        .collect();
    assert!(found.contains(&("DELETE".into(), "/api/keys/{key}".into(), Severity::High)), "{found:#?} {:#?}", report.finding_details.iter().map(|f| (&f.rationale, &f.peer_group_id)).collect::<Vec<_>>());
    assert!(
        found.contains(&("GET".into(), "/api/indexes/{uid}/stats".into(), Severity::Low))
            && !found.iter().any(|(_, path, severity)| path == "/api/indexes/{uid}/stats" && *severity != Severity::Low),
        "{found:#?}"
    );
}

#[test]
fn archer_toml_declares_public_routes_and_dismisses_reviewed_findings() {
    let config = r#"
[[public]]
method = "GET"
path = "/api/indexes/{id}/stats"
reason = "stats are public"

[[dismiss]]
method = "delete"
path = "/api/keys/*"
category = "MissingAuthorization"
reason = "delete_key checks the key store itself"

[[dismiss]]
path = "/api/gone"
reason = "stale rule"
"#;
    let repo = TempRepo::new(
        "f36-config",
        &[
            ("main.rs", include_str!("../../tests/fixtures/probes/drift/f36_route_tables.rs")),
            ("archer.toml", config),
        ],
    );
    let report = repo.analyze();
    assert!(report.config.is_some());
    assert!(report.finding_details.iter().all(|finding| finding.suspicious_route.path != "/api/indexes/{uid}/stats"
        && finding.suspicious_route.path != "/api/keys/{key}"
        || finding.suspicious_route.method == "PATCH"));
    assert_eq!(report.dismissed.len(), 1);
    assert_eq!(report.dismissed[0].reason, "delete_key checks the key store itself");
    assert!(report.unjudged.iter().any(|route| route.reason == UnjudgedReason::DeclaredPublic
        && route.path == "/api/indexes/{uid}/stats"
        && route.detail == "stats are public"));
    assert!(report.warnings.iter().any(|warning| warning.contains("`/api/gone` matches no finding")), "{:?}", report.warnings);

    let invalid = TempRepo::new(
        "f36-bad-config",
        &[("main.rs", "fn main() {}"), ("archer.toml", "[[dismiss]]\npath = \"/x\"\ncategory = \"Nope\"\nreason = \"r\"\n")],
    );
    let error = analyze_repository(&invalid.0).unwrap_err().to_string();
    assert!(error.contains("unknown finding category `Nope`"), "{error}");
}

#[test]
fn a_route_calling_the_identity_source_without_the_peers_requirement_is_reported() {
    let report = drift_fixture(
        "f37",
        include_str!("../../tests/fixtures/probes/drift/f37_requirement_arguments.rs"),
    );
    let found: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| (finding.suspicious_route.method.clone(), finding.suspicious_route.path.clone(), finding.severity))
        .collect();
    assert_eq!(
        found,
        [
            ("DELETE".to_string(), "/origins/{origin}/invitations/{id}".to_string(), Severity::Medium),
            ("GET".to_string(), "/origins/{origin}/members".to_string(), Severity::Low),
        ],
        "{:#?}",
        report.finding_details.iter().map(|finding| &finding.rationale).collect::<Vec<_>>()
    );
    assert!(report.finding_details[0].rationale.contains("`Some(Role::Administrator)`"));
}

#[test]
fn f38_extractors_are_judged_by_their_from_request_body() {
    let report = drift_fixture(
        "f38",
        include_str!("../../tests/fixtures/probes/drift/f38_learned_extractors.rs"),
    );
    let members = route_at(&report, "/api/team/members");
    assert!(has_evidence(members, AuthEvidenceKind::RoleCheck, "OwnerOnly"));
    assert!(
        members
            .authorization
            .iter()
            .any(|evidence| evidence.requirements == ["owner"]),
        "{:?}",
        members.authorization
    );
    assert!(has_evidence(
        route_at(&report, "/api/team/archive"),
        AuthEvidenceKind::RoleCheck,
        "StaffGate"
    ));
    let rename = route_at(&report, "/api/team/rename");
    assert!(has_evidence(rename, AuthEvidenceKind::IdentityExtraction, "LoggedUser"));
    // A data extractor that rejects malformed requests checks no caller.
    assert!(
        !rename
            .authorization
            .iter()
            .any(|evidence| evidence.mechanism == "TeamData"),
        "{:?}",
        rename.authorization
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "POST", "/api/team/rename")]
    );
}

#[test]
fn f39_a_write_below_every_other_route_of_its_resource_is_reported() {
    let report = drift_fixture(
        "f39",
        include_str!("../../tests/fixtures/probes/drift/f39_write_below_reads.rs"),
    );
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "POST", "/api/org/api_key")]
    );
    let create = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/api/org/api_key")
        .unwrap();
    assert_eq!(create.severity, Severity::High);
    assert!(create.rationale.contains("its reads included"), "{}", create.rationale);
    assert!(
        report
            .unjudged
            .iter()
            .any(|route| route.path == "/api/billing/webhook"
                && route.reason == UnjudgedReason::WellKnownPublic),
    );
}

#[test]
fn f40_tenant_comparisons_and_membership_helpers_are_object_level_checks() {
    let report = drift_fixture(
        "f40",
        include_str!("../../tests/fixtures/probes/drift/f40_tenant_checks.rs"),
    );
    for method in ["GET", "PUT", "PATCH"] {
        let route = report
            .routes
            .iter()
            .find(|route| route.path == "/api/projects/{project_id}" && route.method == method)
            .unwrap();
        assert_eq!(route.best_tier(), EvidenceTier::Resource, "{method} {:?}", route.authorization);
    }
    let team = route_at(&report, "/api/teams/{team_id}");
    assert!(has_evidence(team, AuthEvidenceKind::OwnershipCheck, "verify_member"));
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "DELETE", "/api/projects/{project_id}")]
    );
}

#[test]
fn f42_resource_method_shorthand_path_arrays_and_forwarding_configure_closures() {
    let report = drift_fixture(
        "f42",
        include_str!("../../tests/fixtures/probes/drift/f42_resource_shorthand.rs"),
    );
    let mut routes: Vec<String> = report
        .routes
        .iter()
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    routes.sort();
    // Each route once: `.configure(|c| f(c))` expands `f` a single time, and
    // `map.get(..)` is not a route.
    assert_eq!(
        routes,
        [
            "DELETE /api/users/{id}",
            "GET /api/ping",
            "GET /api/status",
            "GET /api/users",
            "GET /api/users/{id}",
            "PATCH /api/users/{id}/restore",
            "POST /api/auth/login",
            "POST /api/users",
            "PUT /api/users/{id}",
        ]
    );
    assert_eq!(route_at(&report, "/api/users/{id}/restore").handler.as_deref(), Some("restore_user"));
    assert!(has_evidence(route_at(&report, "/api/users"), AuthEvidenceKind::RoleCheck, "AdminUser"));
    assert_eq!(
        reported(&report),
        [finding(MissingAuthorization, "PATCH", "/api/users/{id}/restore")]
    );
}
#[test]
fn f43_loops_macros_services_aliases_any_guards_scope_modules_and_route_tables() {
    let report = drift_fixture(
        "f43",
        include_str!("../../tests/fixtures/probes/drift/f43_route_forms.rs"),
    );
    let mut routes: Vec<String> = report
        .routes
        .iter()
        .map(|route| format!("{} {}", route.method, route.path))
        .collect();
    routes.sort();
    assert_eq!(
        routes,
        [
            "DELETE /scoped/x",
            "GET /admin/stats",
            "GET /alias",
            "GET /any",
            "GET /loop/a",
            "GET /loop/b",
            "GET /m/a",
            "GET /m/b",
            "GET /var/a",
            "GET /var/b",
            "POST /any",
            "POST /signin",
            "POST /typed",
            "PUT /foreign",
            "UNKNOWN /svc",
        ]
    );
    assert_eq!(route_at(&report, "/m/b").handler.as_deref(), Some("h2"));
    // Every route-like call site was read; the fallback service is not a route.
    assert_eq!(report.coverage.route_sites, report.coverage.route_sites_read);
    assert!(report.coverage.unread_route_sites.is_empty());
}

#[test]
fn f44_helper_middleware_closures_attribute_options_req_data_and_check_methods() {
    let report = drift_fixture(
        "f44",
        include_str!("../../tests/fixtures/probes/drift/f44_auth_forms.rs"),
    );
    let kinds = |path: &str| -> Vec<AuthEvidenceKind> {
        route_at(&report, path).authorization.iter().map(|evidence| evidence.kind.clone()).collect()
    };
    for path in ["/helper", "/attr", "/closure", "/me"] {
        assert!(kinds(path).contains(&AuthEvidenceKind::IdentityExtraction), "{path}: {:?}", kinds(path));
    }
    assert!(
        route_at(&report, "/helper")
            .authorization
            .iter()
            .any(|evidence| evidence.mechanism.contains("returned by `get_middleware()`"))
    );
    assert!(
        kinds("/alerts").iter().any(|kind| *kind != AuthEvidenceKind::Unknown),
        "{:?}",
        kinds("/alerts")
    );
}

#[test]
fn unread_route_sites_are_reported_and_zero_peer_groups_explained() {
    // `make(web::get())` hands the route constructor to a function Archer
    // does not follow: the route is missing, and the report says where.
    let report = drift_fixture(
        "unread_sites",
        r#"
use actix_web::{web, App};
async fn h() {}
fn make(route: actix_web::Route) -> actix_web::Resource { web::resource("/x").route(route) }
fn main() { App::new().route("/a", web::get().to(h)).service(make(web::get().to(h))); }
"#,
    );
    assert_eq!(report.coverage.unread_route_sites.len(), 1, "{:?}", report.coverage.unread_route_sites);
    assert!(report.coverage.unread_route_sites[0].contains(":5 "));
    assert!(report.warnings.iter().any(|warning| warning.contains("did not read as a route")));
    assert!(report.warnings.iter().any(|warning| warning.starts_with("no peer groups formed")));
}

#[test]
fn peer_groups_form_at_every_level_and_say_how() {
    let report = drift_fixture(
        "f45",
        include_str!("../../tests/fixtures/probes/drift/f45_peer_formation.rs"),
    );
    let found: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| {
            (
                finding.category,
                finding.severity,
                finding.suspicious_route.method.clone(),
                finding.suspicious_route.path.clone(),
            )
        })
        .collect();
    // Item 3: the lone unprotected read is judged at its API version root,
    // at most Low, and the finding names the level and the levels passed over.
    assert!(
        found.contains(&(
            FindingCategory::MissingAuthentication,
            Severity::Low,
            "GET".into(),
            "/api/v1/notes/all".into()
        )),
        "{found:#?}"
    );
    let notes = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/api/v1/notes/all")
        .unwrap();
    assert!(notes.rationale.contains("API version level (/api/v1)"), "{}", notes.rationale);
    assert!(notes.rationale.contains("(grouping: resource /api/v1/notes/all"), "{}", notes.rationale);
    // Item 7: a GET whose handler writes is compared with the writes.
    let empty = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/shop/cart/{cart}/empty")
        .expect("GET /shop/cart/{cart}/empty is held to the cart writes");
    assert_eq!(empty.category, FindingCategory::MissingAuthentication);
    assert!(empty.rationale.contains("calls `delete_cart_items`"), "{}", empty.rationale);
    // Item 8: a name alone does not exclude a route.
    assert!(
        found.iter().any(|(_, _, _, path)| path == "/account/verify"),
        "{found:#?}"
    );
    let reason = |path: &str| {
        report
            .unjudged
            .iter()
            .find(|route| route.path == path)
            .map(|route| route.reason)
    };
    assert_eq!(reason("/account/login"), Some(UnjudgedReason::AuthenticationEndpoint));
    // Item 2: an unprotected group is formed with tier None.
    assert_eq!(reason("/pages/about"), None);
    let pages = report
        .peer_groups
        .iter()
        .find(|group| group.prefix == "/pages")
        .expect("the /pages group is formed");
    assert!(pages.description.contains("tier None"), "{}", pages.description);
    // Item 11: the coverage counts.
    assert_eq!(report.coverage.routes_total, report.routes.len());
    assert!(report.coverage.routes_compared >= 9, "{:?}", report.coverage.routes_compared);
    assert_eq!(report.coverage.peer_groups, report.peer_groups.len());
}

#[test]
fn path_segments_normalise_slashes_and_parameters() {
    use super::drift::{is_catch_all_segment, is_dynamic_segment, path_segments};
    assert!(path_segments("").is_empty());
    assert!(path_segments("/").is_empty());
    assert_eq!(path_segments("/users/"), ["users"]);
    assert_eq!(path_segments("users"), ["users"]);
    // A parameter pattern with a slash stays one segment.
    assert_eq!(path_segments("/files/{path:.*/raw}"), ["files", "{path:.*/raw}"]);
    assert!(is_dynamic_segment("{id:\\d+}"));
    assert!(is_dynamic_segment("{tail}*"));
    assert!(is_catch_all_segment("{tail}*"));
    assert!(is_catch_all_segment("{rest:.*}"));
    assert!(!is_catch_all_segment("{id}"));
    assert!(!is_catch_all_segment("{id:\\d+}"));
}

#[test]
fn no_peer_groups_warning_names_the_cause() {
    let repo = TempRepo::new(
        "no-groups",
        &[(
            "main.rs",
            "use actix_web::{web, App};
fn app() { App::new().route(\"/login\", web::post().to(login)).route(\"/health\", web::get().to(health)); }
async fn login() {}
async fn health() {}
",
        )],
    );
    let report = repo.analyze();
    assert!(report.peer_groups.is_empty());
    let warning = report
        .warnings
        .iter()
        .find(|warning| warning.starts_with("no peer groups formed"))
        .unwrap();
    assert!(warning.contains("most routes were left out because"), "{warning}");
}

#[test]
fn flat_apps_form_a_root_group_and_shared_unknown_middleware_does_not_block_groups() {
    let report = drift_fixture(
        "f46",
        include_str!("../../tests/fixtures/probes/drift/f46_flat_app_and_shared_unknown.rs"),
    );
    let found: Vec<_> = report
        .finding_details
        .iter()
        .map(|finding| (finding.category, finding.severity, finding.suspicious_route.path.clone()))
        .collect();
    // Item 4: the root-level routes are compared in one root group, so the
    // odd one out is reported, at Low. (Here another Low check, the peers'
    // use of the caller, reports it first; the root group's finding yields.)
    assert!(
        found.iter().any(|(_, severity, path)| path == "/reports" && *severity == Severity::Low),
        "{found:#?}"
    );
    assert!(report.peer_groups.iter().any(|group| group.level == GroupLevel::App));
    // Item 9: `TeamGate` wraps every route of /team, so the odd one out is
    // reported as missing authentication, not as unverified.
    assert!(
        found.contains(&(FindingCategory::MissingAuthentication, Severity::High, "/team/export".into())),
        "{found:#?}"
    );
    assert!(report.unjudged.iter().all(|route| !route.path.starts_with("/team")));
}

#[test]
fn well_known_names_ignore_separators() {
    assert!(is_well_known_public_route(&route("GET", "/health_check", "", "NONE")));
    assert!(is_well_known_public_route(&route("GET", "/api/health-check", "/api", "NONE")));
    assert!(!is_well_known_public_route(&route("GET", "/admin/health_check", "/admin", "NONE")));
}

#[test]
fn exempt_lists_walked_in_a_loop_are_read() {
    let report = drift_fixture(
        "f47",
        include_str!("../../tests/fixtures/probes/drift/f47_exempt_list_loop.rs"),
    );
    let evidence = |path: &str| -> Vec<(AuthEvidenceKind, String)> {
        report
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("no route {path}"))
            .authorization
            .iter()
            .map(|evidence| (evidence.kind.clone(), evidence.mechanism.clone()))
            .collect()
    };
    // The constant list in `constants` is read through the `for` loop and
    // the `authenticate_pass` flag: its entries are exempt, the rest checked.
    for exempt in ["/api/ping", "/api/auth/signup", "/api/auth/login", "/api/notes/export"] {
        assert!(evidence(exempt).is_empty(), "{exempt}: {:?}", evidence(exempt));
    }
    for checked in ["/api/notes", "/api/notes/{id}", "/api/auth/logout"] {
        let found = evidence(checked);
        assert_eq!(found.len(), 1, "{checked}: {found:?}");
        assert_eq!(found[0].0, AuthEvidenceKind::IdentityExtraction, "{checked}");
        assert!(found[0].1.contains("skips /api/ping*"), "{}", found[0].1);
    }
    // Logout is not on the app's exempt list, so it is compared with its
    // peers; login and signup are.
    let reason = |path: &str| {
        report
            .unjudged
            .iter()
            .find(|route| route.path == path)
            .map(|route| route.reason)
    };
    assert_eq!(reason("/api/auth/login"), Some(UnjudgedReason::AuthenticationEndpoint));
    assert_ne!(reason("/api/auth/logout"), Some(UnjudgedReason::AuthenticationEndpoint));
    // The note export exempted by mistake is the one its peers flag.
    assert_eq!(
        reported(&report),
        [(
            FindingCategory::MissingAuthentication,
            "GET".to_string(),
            "/api/notes/export".to_string()
        )]
    );
}

#[test]
fn path_rule_evidence_says_whether_listed_paths_are_exempt_or_covered() {
    let report = drift_fixture(
        "f28-wording",
        include_str!("../../tests/fixtures/probes/drift/f28_path_conditional_middleware.rs"),
    );
    let mechanism = |path: &str| {
        report
            .routes
            .iter()
            .find(|route| route.path == path)
            .and_then(|route| route.authorization.iter().find(|evidence| evidence.mechanism.contains("path rule")))
            .map(|evidence| evidence.mechanism.clone())
            .unwrap_or_default()
    };
    // `!logged_in && path != "/api/login"` exempts the login path.
    assert!(mechanism("/api/orders").contains("exempts /api/login"), "{}", mechanism("/api/orders"));
    // `path.contains("/private")` covers only the paths it names.
    assert!(mechanism("/portal/private/drafts").contains("applies only to"), "{}", mechanism("/portal/private/drafts"));
}

#[test]
fn groups_whose_protection_cannot_be_evaluated_are_not_called_public() {
    let repo = TempRepo::new(
        "unevaluated-group",
        &[(
            "main.rs",
            "use actix_web::{web, App};
fn app() { App::new().service(web::scope(\"/notes\").wrap(NoteGate).route(\"/a\", web::post().to(a)).route(\"/b\", web::post().to(b))); }
struct NoteGate;
async fn a() {}
async fn b() {}
",
        )],
    );
    let report = repo.analyze();
    let group = report.peer_groups.iter().find(|group| group.prefix == "/notes").unwrap();
    assert!(group.description.contains("cannot evaluate"), "{}", group.description);
    assert!(!group.description.contains("meant to be public"), "{}", group.description);
}

fn followed_checks_fixture() -> Report {
    TempRepo::new(
        "f48-followed-checks",
        &[
            ("Cargo.toml", CARGO_TOML),
            (
                "src/main.rs",
                include_str!("../../tests/fixtures/probes/drift/f48_followed_checks/main.rs"),
            ),
            (
                "src/store.rs",
                include_str!("../../tests/fixtures/probes/drift/f48_followed_checks/store.rs"),
            ),
        ],
    )
    .analyze()
}

fn evidence_symbols(report: &Report, method: &str, path: &str) -> Vec<(AuthEvidenceKind, String)> {
    report
        .routes
        .iter()
        .find(|route| route.method == method && route.path == path)
        .unwrap_or_else(|| panic!("no route {method} {path}"))
        .authorization
        .iter()
        .map(|evidence| (evidence.kind.clone(), evidence.symbol.clone().unwrap_or_default()))
        .collect()
}

#[test]
fn checks_in_methods_and_service_functions_are_followed() {
    let report = followed_checks_fixture();
    // The routes that skip the check their peers make are the ones reported.
    assert_eq!(
        reported(&report),
        vec![
            (FindingCategory::MissingAuthorization, "DELETE".to_string(), "/boards/{id}".to_string()),
            (FindingCategory::SkipsPeerCheck, "POST".to_string(), "/notes/d".to_string()),
        ]
    );
    // A method of the caller type, two levels deep, is cited with its chain.
    let skipped = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.path == "/notes/d")
        .unwrap();
    assert!(
        skipped.rationale.contains("create_a -> require_account -> `require_active` at"),
        "{}",
        skipped.rationale
    );
    // `store::Boards::rename(..)`, an associated function in another module,
    // and the helper behind a recursive one are both followed to the owner
    // comparison.
    for method in ["PATCH", "POST", "PUT"] {
        let found = evidence_symbols(&report, method, "/boards/{id}");
        assert!(
            found.iter().any(|(kind, symbol)| *kind == AuthEvidenceKind::OwnershipCheck
                && symbol.contains("ensure_owner -> caller . account != Some (board . owner)")),
            "{method}: {found:?}"
        );
    }
    let missing = report
        .finding_details
        .iter()
        .find(|finding| finding.suspicious_route.method == "DELETE")
        .unwrap();
    assert!(missing.rationale.contains("ensure_owner"), "{}", missing.rationale);
    assert!(missing.rationale.contains("store.rs:"), "{}", missing.rationale);
}

#[test]
fn build_variants_and_deep_helper_chains_are_followed() {
    let report = drift_fixture(
        "f49",
        include_str!("../../tests/fixtures/probes/drift/f49_build_variants_and_deep_helpers.rs"),
    );
    // `ops::remove` has a `full` and a `lite` variant; the handler is built
    // with `full`, whose variant makes the check.
    let removed = evidence_symbols(&report, "DELETE", "/items/{id}");
    assert!(
        removed.contains(&(AuthEvidenceKind::RoleCheck, "remove -> require_admin".to_string())),
        "{removed:?}"
    );
    // Four calls deep: past the old limit of three.
    let replaced = evidence_symbols(&report, "PUT", "/items/{id}");
    assert!(
        replaced.contains(&(
            AuthEvidenceKind::RoleCheck,
            "step_one -> step_two -> step_three -> step_four -> require_admin".to_string()
        )),
        "{replaced:?}"
    );
}

#[test]
fn structural_checks_need_a_branch_on_the_callers_own_value() {
    let repo = TempRepo::new(
        "structural-checks",
        &[(
            "main.rs",
            "use actix_web::{web, App, HttpResponse};
pub struct AuthenticatedUser { pub id: u64, pub suspended: bool }
pub struct Fault;
fn app() { App::new().route(\"/a\", web::post().to(a)).route(\"/b\", web::post().to(b)); }
async fn a(user: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    if user.suspended { return Err(Fault); }
    Ok(HttpResponse::Ok().finish())
}
async fn b(user: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    match lookup(user.id) { Some(_) => Ok(HttpResponse::Ok().finish()), None => Err(Fault) }
}
fn lookup(id: u64) -> Option<u64> { Some(id) }
",
        )],
    );
    let report = repo.analyze();
    let structural = |path: &str| -> Vec<String> {
        evidence_symbols(&report, "POST", path)
            .into_iter()
            .filter(|(kind, symbol)| *kind == AuthEvidenceKind::IdentityExtraction && symbol != "AuthenticatedUser")
            .map(|(_, symbol)| symbol)
            .collect()
    };
    // A branch on the caller's attribute is a check on the caller.
    assert_eq!(structural("/a"), vec!["user . suspended".to_string()]);
    // A branch on what a free function returns for the caller's id is not:
    // the result need not be about the caller.
    assert!(structural("/b").is_empty(), "{:?}", structural("/b"));
}

#[test]
fn a_resolved_method_replaces_the_not_analyzed_note() {
    let repo = TempRepo::new(
        "resolved-method-note",
        &[(
            "main.rs",
            "use actix_web::{web, App, HttpResponse};
pub struct AuthenticatedUser { pub id: u64 }
impl AuthenticatedUser {
    pub fn display_id(&self) -> u64 { self.id }
}
fn app() { App::new().route(\"/a\", web::get().to(a)); }
async fn a(user: AuthenticatedUser) -> HttpResponse {
    let _ = user.display_id();
    HttpResponse::Ok().finish()
}
",
        )],
    );
    let report = repo.analyze();
    // `display_id` is a getter: once resolved, nothing is left unanalyzed.
    let found = evidence_symbols(&report, "GET", "/a");
    assert!(
        !found.iter().any(|(kind, _)| *kind == AuthEvidenceKind::Delegated),
        "{found:?}"
    );
}

#[test]
fn a_helpers_check_on_its_caller_parameter_needs_the_callers_own_value() {
    let repo = TempRepo::new(
        "structural-through-helpers",
        &[(
            "main.rs",
            "use actix_web::{web, App, HttpResponse};
pub struct AuthenticatedUser { pub id: u64, pub suspended: bool }
pub struct Submission { pub author: AuthenticatedUser }
pub struct Fault;
fn app() { App::new().route(\"/c\", web::post().to(c)).route(\"/d\", web::post().to(d)); }
fn ensure_active(user: &AuthenticatedUser) -> Result<(), Fault> {
    if user.suspended { return Err(Fault); }
    Ok(())
}
async fn c(user: AuthenticatedUser) -> Result<HttpResponse, Fault> {
    ensure_active(&user)?;
    Ok(HttpResponse::Ok().finish())
}
async fn d(form: web::Json<Submission>) -> Result<HttpResponse, Fault> {
    ensure_active(&form.author)?;
    Ok(HttpResponse::Ok().finish())
}
",
        )],
    );
    let report = repo.analyze();
    let structural = |path: &str| -> Vec<String> {
        evidence_symbols(&report, "POST", path)
            .into_iter()
            .filter(|(kind, symbol)| *kind == AuthEvidenceKind::IdentityExtraction && symbol != "AuthenticatedUser")
            .map(|(_, symbol)| symbol)
            .collect()
    };
    // The handler passes its own caller: the helper's branch checks it.
    assert_eq!(structural("/c"), vec!["ensure_active -> user . suspended".to_string()]);
    // A user record read from the request body is not the caller.
    assert!(structural("/d").is_empty(), "{:?}", structural("/d"));
}
