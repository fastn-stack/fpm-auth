use oauth2::{
    TokenResponse
};
pub struct AppState {
    pub oauth: oauth2::basic::BasicClient,
}
#[derive(Debug)]
pub struct RepoObj {
    pub repo_owner:String,
    pub repo_title:String
}
pub async fn index(session: actix_session::Session) -> actix_web::HttpResponse {
    let access_token = session.get::<String>("access_token").unwrap();
    let user_login = session.get::<String>("user_login").unwrap();
    let link = if access_token.is_some() { "auth/logout/" } else { "auth/login/" };
    let link_title=if access_token.is_some() { "Logout"} else { "Login" };
    let welcome_msg;
    if user_login.is_some(){
        welcome_msg=format!("{}{}","Hello ",user_login.clone().unwrap_or("".to_string()));
    }else{
        welcome_msg=String::from("Welcome. Please first login: ");
    };
    //let welcome_msg=if user_login.is_some() { if user_login.is_some(){user_login.clone()} } else { "Welcome. Please login first: " };
    
    let html = format!(
        r#"<html>
        <head><title>FDM</title></head>
        <body>
            {} <a href="/{}">{}</a>
        </body>
    </html>"#,
    welcome_msg,
        link,
        link_title
    );

    actix_web::HttpResponse::Ok().body(html)
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
session.remove("user_login");
session.remove("user_email");
session.remove("user_fullname");
actix_web::HttpResponse::Found()
    .append_header((actix_web::http::header::LOCATION, "/auth/".to_string()))
    .finish()
}
/*#[derive(serde::Deserialize)]
pub struct IdentityInput {
    github_starred:String
}*/
pub async fn get_identity(session: actix_session::Session,
    req: actix_web::HttpRequest,) -> actix_web::HttpResponse {
    let user_email = session.get::<String>("user_email").unwrap();
    let user_login = session.get::<String>("user_login").unwrap();
//pub async fn get_identity(session: actix_session::Session,url:actix_web::web::Path<String>) -> actix_web::HttpResponse {
    //let mut repo_list: Vec<RepoObj> = Vec::new();
    let mut repo_list: Vec<String> = Vec::new();
    let access_token = session.get::<String>("access_token").unwrap();
    let uri_string=req.uri();
    let final_url:String=format!("{}{}","http://localhost:9090",uri_string.clone().to_string());
    let request_url = url::Url::parse(&final_url.to_string()).unwrap();
    let pairs = request_url.query_pairs();
    for pair in pairs{
        if pair.0=="github_starred"{
            if !repo_list.contains(&pair.1.to_string()){
                repo_list.push(pair.1.to_string());
            }
           
        }
    }
if access_token.is_some() {
let mut all_found_repo:String=String::from("");
    let reporesp=get_starred_repo(access_token.clone().unwrap_or("".to_string()),&repo_list).await;
    match reporesp {
        Ok(reporesp) => {
            //return actix_web::HttpResponse::Ok().content_type("application/json")
            //.json(reporesp);
if reporesp.len()>0{
    for repo in reporesp{
        //all_found_repo
        if all_found_repo==""{
            all_found_repo=format!("{}{}","github-starred:",repo);
        }else{
            all_found_repo=format!("{}{}{}",all_found_repo,",",repo);
        }
        
    }
    
}else{
    all_found_repo=String::from("");
}
            
            let html = format!(
                r#"<html>
                <head><title>FDM</title></head>
                <body>
                github-username:{}<br/>gmail-email:{}<br/>{}
                </body>
            </html>"#,
            user_login.clone().unwrap_or("".to_string()),
            user_email.clone().unwrap_or("".to_string()),
            all_found_repo.clone(),
            );
        
            actix_web::HttpResponse::Ok().body(html)
        }
        Err(e) => {
            return actix_web::HttpResponse::BadRequest().content_type("application/json")
            .json(e.to_string());
    }
    }
    

}else{
    return actix_web::HttpResponse::BadRequest().content_type("application/json")
        .json("No record found.");
}

}

#[derive(serde::Deserialize)]
pub struct AuthRequest {
code: String,
state: String,
}
pub async fn auth(
session: actix_session::Session,
data: actix_web::web::Data<AppState>,
params: actix_web::web::Query<AuthRequest>,
) -> actix_web::HttpResponse {
let code = oauth2::AuthorizationCode::new(params.code.clone());
let _state = oauth2::CsrfToken::new(params.state.clone());
let access_token;
let token_res = &data.oauth
    .exchange_code(code)
    .request_async(oauth2::reqwest::async_http_client)
    .await;
    if let Ok(token) = token_res {
        access_token=token.access_token().clone().secret().to_string();
        session.insert("access_token", access_token.clone()).unwrap();
        
        let userresp=user_details(access_token.clone()).await;
        match userresp {
            Ok(userresp) => {
                session.insert("user_login", userresp.get("login").clone()).unwrap();
                session.insert("user_email", userresp.get("email").clone()).unwrap();
                session.insert("user_fullname", userresp.get("name").clone()).unwrap();

            }
            Err(_) => {
        }
        }
    }else{

    }
    actix_web::HttpResponse::Found()
    .append_header((actix_web::http::header::LOCATION, "/auth/".to_string()))
    .finish()
}
async fn user_details(access_token:String) -> Result<serde_json::value::Value,reqwest::Error> {

    let token_val=format!("{}{}", String::from("token "), access_token);
    
    let request_obj=reqwest::Client::new()
        .get("https://api.github.com/user")
        .header(reqwest::header::AUTHORIZATION, token_val)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::USER_AGENT, "Actix-web")
        .send()
        .await?;
        let resp: serde_json::Value = request_obj.json().await?;
        Ok(resp)
    }
    async fn get_starred_repo(access_token:String,repo_list:&Vec<String>) -> Result<Vec<String>,reqwest::Error> {
        let token_val=format!("{}{}", String::from("Bearer "), access_token);
        let mut starred_repo:Vec<String>=vec![];
        //let api_url=format!("{}{}", String::from("https://api.github.com/user/starred/"),repo_name);
        let api_url=format!("{}", String::from("https://api.github.com/user/starred"));
        let request_obj=reqwest::Client::new()
        .get(api_url.clone())
        .header(reqwest::header::AUTHORIZATION, token_val)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::USER_AGENT, "Actix-web")
        .send()
        .await?;
        let resp:serde_json::Value = request_obj.json().await?;
       
        if resp.as_array().unwrap().len()>0
        {
        for repo in repo_list{
        for respobj in resp.as_array().unwrap().iter(){
        if repo==respobj.get("full_name").unwrap(){
           starred_repo.push(respobj.get("full_name").unwrap().to_string());
        }
        }
        }
        }
        Ok(starred_repo)
     
        
    }