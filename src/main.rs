#[macro_use]
extern crate actix_web;
#[macro_use]
extern crate diesel;

use {
    actix_web::{web,middleware, App,HttpResponse, HttpServer},
    actix_web::web::Data,
    actix_web::http::header,
    diesel::r2d2::ConnectionManager,
    diesel::PgConnection,
    r2d2::{Pool, PooledConnection},
    std::{env, io},
};
use http::{HeaderMap, Method};
use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::{
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
fn main() {
    println!("Hello, world!");
}
