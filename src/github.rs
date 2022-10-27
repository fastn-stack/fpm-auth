use oauth2::{
    TokenResponse
};
pub struct AppState {
    pub oauth: oauth2::basic::BasicClient,
}
pub async fn login(data: actix_web::web::Data<AppState>) -> actix_web::HttpResponse {

    //let (authorize_url, csrf_state) = &data.oauth
    let authorize_url = &data.oauth
    .authorize_url(oauth2::CsrfToken::new_random)
    .add_scope(oauth2::Scope::new("public_repo".to_string()))
    .add_scope(oauth2::Scope::new("user:email".to_string()))
    .url();
    actix_web::HttpResponse::Found()
    .append_header((actix_web::http::header::LOCATION, authorize_url.0.to_string()))
    .finish()
   // HttpResponse::Ok().body(format!("username:"))
}

pub async fn logout(session: actix_session::Session) -> actix_web::HttpResponse {
session.remove("access_token");
actix_web::HttpResponse::Found()
    .append_header((actix_web::http::header::LOCATION, "/".to_string()))
    .finish()
}

pub async fn get_identity(session: actix_session::Session) -> actix_web::HttpResponse {
let access_token = session.get::<String>("access_token").unwrap();
if access_token.is_some() {
    
    match userdetails(access_token.clone().unwrap_or("".to_string())).await {
        Ok(val) => {
            //dbg!(val.get("login").clone());    
            dbg!(val);
        },
        Err(e) => {
            dbg!(e);
        },
    };
    let link ="logout"; 
           let html = format!(
               r#"<html>
               <head><title>Identity</title></head>
               <body>
                   {} <a href="/{}">{}</a>
               </body>
           </html>"#,
           access_token.unwrap_or("".to_string()),
               link,
               link
           );
       
           actix_web::HttpResponse::Ok().body(html)
}else{
    let link = "login";
    let html = format!(
        r#"<html>
        <head><title>Identity</title></head>
        <body>
            <a href="/{}">{}</a>
        </body>
    </html>"#,
        link,
        link
    );

    actix_web::HttpResponse::Ok().body(html)
}

}
async fn userdetails(access_token:String) -> Result<serde_json::value::Value,awc::error::HttpError> {

let token_val=format!("{}{}", String::from("token "), access_token);

let clientnew = awc::Client::new();

let request = clientnew
     .get("https://api.github.com/user")    // <- Create request builder
     .insert_header(("User-Agent", "Actix-web"))
     .insert_header(("accept", "application/json"))
     .insert_header(("authorization", token_val.clone()));


     match request.send().await{
        Ok(mut val) => {

            match val.body().await{
                Ok(bdy)=>{
                    
                    let v: serde_json::value::Value=serde_json::from_slice(&bdy).unwrap();
                    Ok(v)
                  
                }
                Err(e) => {

                   Err(e).unwrap()
                   
                },
            }
        },
        Err(e) => {
            Err(e).unwrap()

        },
    }

}
#[derive(serde::Deserialize)]
pub struct AuthRequest {
code: String,
state: String,
}
/*#[derive(Deserialize, Debug)]
pub struct UserInfo {
login: String,
avatar_url: String,
url: String,
organizations_url: String,
repos_url: String,
name: String,
company: String,
email: String,
}*/

pub async fn auth(
session: actix_session::Session,
data: actix_web::web::Data<AppState>,
params: actix_web::web::Query<AuthRequest>,
) -> actix_web::HttpResponse {
let code = oauth2::AuthorizationCode::new(params.code.clone());
let _state = oauth2::CsrfToken::new(params.state.clone());
let access_token;
// Exchange the code with a token.
let token_res = &data.oauth
    .exchange_code(code)
    .request_async(oauth2::reqwest::async_http_client)
    .await;
    if let Ok(token) = token_res {
        access_token=token.access_token().clone().secret().to_string();
        session.insert("access_token", access_token.clone()).unwrap();
        match userdetails(access_token.clone()).await {
            Ok(val) => {    
                //dbg!(val);
                dbg!(val.get("login").clone());
            },
            Err(e) => {
                dbg!(e);
            },
        };
        //access_token.secret().to;
        let html = format!(
            r#"<html>
            <head><title>OAuth2 Test</title></head>
            <body>
                Gitlab user info:
                <pre>{}</pre>
                <a href="/">Home</a>
            </body>
        </html>"#,
        access_token
        );
        actix_web::HttpResponse::Ok().body(html)
    }else{
        let html = format!(
            r#"<html>
            <head><title>OAuth2 Test</title></head>
            <body>
                Gitlab user info:
                <pre></pre>
                <a href="/">Home</a>
            </body>
        </html>"#,);
        actix_web::HttpResponse::Ok().body(html)
    }

}