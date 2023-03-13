use db::db_connection::db_connection;
use jsonwebtoken::{self, EncodingKey};
use queries::{password_is_valid, select_user_by_email};
use salvo::http::{Method, StatusError};
use salvo::prelude::*;
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
pub const SECRET_KEY: &str = "YOUR SECRET_KEY JWT CODO_MATON TOKEN";

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    mail: String,
    exp: i64,
}

#[derive(Serialize, Deserialize, Extractible, Debug)]
#[extract(default_source(from = "body", format = "json"))]
struct User {
    mail: String,
    password: String,
}

#[handler]
pub async fn sign_in(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
) -> anyhow::Result<()> {
    let db_connect: DatabaseConnection = db_connection().await.expect("Error");
    if req.method() == Method::POST {
        let user: User = req.extract().await.unwrap();
        let (mail, password) = (user.mail, user.password);
        println!("mail: {:#?}", mail);
        println!("password: {:#?}", password);

        let email_is_matched = select_user_by_email(db_connect, mail.clone())
            .await
            .expect("not matched");

        println!("email_is_matched: {:#?}", email_is_matched);
        if !validate(&mail, &password) {
            res.render(Text::Json("Not Authorized"));
            return Ok(());
        }
        let exp = OffsetDateTime::now_utc() + Duration::days(14);
        let claim = JwtClaims {
            mail,
            exp: exp.unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claim,
            &EncodingKey::from_secret(SECRET_KEY.as_bytes()),
        )?;
        println!("{:#?}", token);
        res.render(Redirect::other(&format!("/?jwt_token={}", token)));
    } else {
        match depot.jwt_auth_state() {
            JwtAuthState::Authorized => {
                let data = depot.jwt_auth_data::<JwtClaims>().unwrap();
                res.render(Text::Json(format!(
                    "Hi {}, have logged in successfully!",
                    data.claims.mail
                )));
            }
            JwtAuthState::Unauthorized => {
                res.render(Text::Json("Not Authorized"));
            }
            JwtAuthState::Forbidden => {
                res.set_status_error(StatusError::forbidden());
            }
        }
    }
    Ok(())
}

fn validate(mail: &str, password: &str) -> bool {
    mail == "root" && password == "pwd"
}
