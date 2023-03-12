use jsonwebtoken::{self, EncodingKey};
use salvo::http::{Method, StatusError};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

pub const SECRET_KEY: &str = "YOUR SECRET_KEY JWT CODO_MATON TOKEN";

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    mail: String,
    exp: i64,
}

#[handler]
pub async fn index(req: &mut Request, depot: &mut Depot, res: &mut Response) -> anyhow::Result<()> {
    if req.method() == Method::POST {
        let (mail, password) = (
            req.query::<String>("mail").unwrap_or_default(),
            req.query::<String>("password").unwrap_or_default(),
            // req.form::<String>("username").await.unwrap_or_default(),
            // req.form::<String>("password").await.unwrap_or_default(),
        );
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

// static LOGIN_HTML: &str = r#"<!DOCTYPE html>
// <html>
//     <head>
//         <title>JWT Auth Demo</title>
//     </head>
//     <body>
//         <h1>JWT Auth</h1>
//         <form action="/" method="post">
//         <label for="username"><b>Username</b></label>
//         <input type="text" placeholder="Enter Username" name="username" required>

//         <label for="password"><b>Password</b></label>
//         <input type="password" placeholder="Enter Password" name="password" required>

//         <button type="submit">Login</button>
//     </form>
//     </body>
// </html>
// "#;
