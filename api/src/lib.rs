// use database_connection::db_connection;
use auth::jwt_auth::{index, JwtClaims, SECRET_KEY};
use db::db_connection::db_connection;
use jsonwebtoken::{self, EncodingKey};
use salvo::{__private::tracing, jwt_auth::QueryFinder, prelude::*};

#[handler]
async fn hello_world() -> &'static str {
    "Hello there!"
}

#[handler]

async fn hello_by_id(req: &mut Request) -> String {
    req.params().get("id").cloned().unwrap_or_default()
}

#[tokio::main]
pub async fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("Listening on http://0.0.0.0:7878");

    db_connection().await.expect("Error");

    let auth_handler: JwtAuth<JwtClaims> = JwtAuth::new(SECRET_KEY.to_owned())
        .with_finders(vec![Box::new(QueryFinder::new("jwt_token"))])
        .with_response_error(false);

    // Define Routing tree
    let routing = Router::with_path("")
        .get(hello_world)
        .push(Router::with_path("<id>").get(hello_by_id));

    // Server Ready
    Server::new(TcpListener::bind("0.0.0.0:7878"))
        .serve(Router::with_hoop(auth_handler).handle(index))
        // .serve(routing)
        .await;
}
