use auth::jwt_auth::{index, JwtClaims, SECRET_KEY};
use db::db_connection::db_connection;
// use jsonwebtoken::{self, EncodingKey};
use entities::*;
use queries::*;
use salvo::http::StatusCode;
use salvo::{__private::tracing, handler, jwt_auth::QueryFinder, prelude::*};
use sea_orm::{entity::*, query::*, DatabaseConnection};
use serde::{Deserialize, Serialize};
use serde_json::json;

type Result<T> = std::result::Result<T, StatusError>;

// #[derive(Clone, Debug)]
// struct AppState {
//     conn: DatabaseConnection,
// }

#[derive(Serialize, Deserialize, Extractible, Debug)]
#[extract(default_source(from = "body", format = "json"))]
struct User {
    firstname: String,
    lastname: String,
    mail: String,
    password: String,
}

#[handler]
async fn hello_world() -> &'static str {
    "Hello there!"
}

#[handler]
async fn hello_by_id(req: &mut Request) -> String {
    req.params().get("id").cloned().unwrap_or_default()
}

#[handler]
async fn sign_up(user_input: User, res: &mut Response) {
    // res.render(Json(user_input));
    let db_connect: DatabaseConnection = db_connection().await.expect("Error");

    let user = entities::user::ActiveModel::from_json(json!(user_input)).expect("not valid");

    create_user(db_connect, user).await.expect("Error");
    res.set_status_code(StatusCode::CREATED)
}

// #[handler]
// async fn sign_in(req: &mut Request) -> String {}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("Listening on http://0.0.0.0:7878");

    db_connection().await.expect("Error");

    // let auth_handler: JwtAuth<JwtClaims> = JwtAuth::new(SECRET_KEY.to_owned())
    //     .with_finders(vec![Box::new(QueryFinder::new("jwt_token"))])
    //     .with_response_error(false);

    // // Define Routing tree
    // let routing = Router::with_path("")
    //     .get(hello_world)
    //     .push(Router::with_path("<id>").get(hello_by_id));

    let routing = Router::with_path("/signup").post(sign_up);
    // .push(Router::with_path("<id>").get(hello_by_id));

    // Server Ready
    Server::new(TcpListener::bind("0.0.0.0:7878"))
        // .serve(Router::with_hoop(auth_handler).handle(index))
        .serve(routing)
        .await;
}
