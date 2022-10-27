
mod discord;
mod github;
mod gmail;
mod slack;
mod telegram;

async fn index(session: actix_session::Session) -> actix_web::HttpResponse {
    let access_token = session.get::<String>("access_token").unwrap();
   

    let link = if access_token.is_some() { "logout" } else { "login" };

    let html = format!(
        r#"<html>
        <head><title>Github Test</title></head>
        <body>
            {} <a href="/{}">{}</a>
        </body>
    </html>"#,
    access_token.unwrap_or("".to_string()),
        link,
        link
    );

    actix_web::HttpResponse::Ok().body(html)
}


#[actix_rt::main]
async fn main() {
    actix_web::HttpServer::new(|| {

        let github_client_id = oauth2::ClientId::new(
            "77c964a9f6a7106a5a0e".to_string()
        );
        let github_client_secret = oauth2::ClientSecret::new(
            "916d6cc2e912082f89891120b929680494467ba6".to_string()
        );
        let auth_url = oauth2::AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
            .expect("Invalid authorization endpoint URL");
        let token_url = oauth2::TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
            .expect("Invalid token endpoint URL");
    
        // Set up the config for the Github OAuth2 process.
        let client = oauth2::basic::BasicClient::new(
            github_client_id,
            Some(github_client_secret),
            auth_url,
            Some(token_url),
        )
        .set_redirect_uri(
            oauth2::RedirectUrl::new("http://localhost:9090/auth".to_string()).expect("Invalid redirect URL"),
        );
        actix_web::App::new()
        .app_data(actix_web::web::Data::new(github::AppState {
                oauth: client,
            }))

            .wrap(
                actix_session::SessionMiddleware::builder(actix_session::storage::CookieSessionStore::default(), actix_web::cookie::Key::from(&[0; 64]))
                    .cookie_secure(false)
                    // customize session and cookie expiration
                    .session_lifecycle(
                        actix_session::config::PersistentSession::default().session_ttl(actix_web::cookie::time::Duration::hours(2)),
                    )
                    .build(),
            )
            .route("/", actix_web::web::get().to(index))
            .route("/login", actix_web::web::get().to(github::login))
            .route("/logout", actix_web::web::get().to(github::logout))
            .route("/auth", actix_web::web::get().to(github::auth))
            .route("/identity", actix_web::web::get().to(github::get_identity))
    })
    .bind("localhost:9090")
    .expect("Can not bind to port 9090")
    .run()
    .await
    .unwrap();
}