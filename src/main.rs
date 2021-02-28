#[macro_use]
extern crate rocket;

use hmac::{Hmac, NewMac};
use jwt::VerifyWithKey;
use mongodb::{
    bson::{de, doc, oid::ObjectId, Document},
    options::ClientOptions,
    Client, Database,
};
use rocket::http::{ContentType, Status};
use rocket::request::{self, FromRequest, Outcome, Request, State};
use rocket::response::Responder;
use rocket_contrib::json::Json;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;

#[derive(Debug)]
struct JWTSecret {
    secret: String,
}

#[derive(Debug)]
struct Connection {
    db: Database,
}

#[derive(Debug, Deserialize)]
struct User {
    email: String,
    password: String,
    role: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserClaims {
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Claims {
    user: UserClaims,
}

impl User {
    async fn find_active_mail(db: &Database, email: &str) -> Option<Self> {
        let doc = doc! {"email": email.to_lowercase()};
        Self::find(db, doc).await
    }

    async fn find_active_id(db: &Database, id: &str) -> Option<Self> {
        match ObjectId::with_string(id) {
            Ok(object_id) => {
                let doc = doc! {"_id": object_id};
                Self::find(db, doc).await
            }
            Err(_) => None,
        }
    }

    async fn find(db: &Database, doc: Document) -> Option<Self> {
        let coll = db.collection("users");
        if let Ok(db_result) = coll.find_one(doc, None).await {
            if let Some(user) = db_result {
                if let Ok(b_user) = de::from_document::<User>(user) {
                    return Some(b_user);
                }
            }
        }
        return None;
    }
}

#[derive(Serialize, Debug)]
struct ApiErrorResponse {
    reason: String,
}

#[derive(Responder, Debug)]
#[response(status = 400, content_type = "json")]
struct ApiError {
    inner: Json<ApiErrorResponse>,
    header: ContentType,
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ApiError;

    async fn from_request(req: &'a Request<'r>) -> request::Outcome<User, Self::Error> {
        let api_key_header = req.headers().get_one("x-api-key");
        match api_key_header {
            Some(api_key) => {
                let connection = req.guard::<State<Connection>>().await.unwrap();
                let secret_key = req.guard::<State<JWTSecret>>().await.unwrap();

                let key: Hmac<Sha256> = Hmac::new_varkey(secret_key.secret.as_bytes()).unwrap();
                let claims: Result<Claims, jwt::Error> = api_key.verify_with_key(&key);
                if let Ok(claims) = claims {
                    let user = User::find_active_id(&connection.db, &claims.user.id).await;
                    if let Some(user) = user {
                        return Outcome::Success(user);
                    } else {
                        return Outcome::Failure((
                            Status::BadRequest,
                            ApiError {
                                inner: Json(ApiErrorResponse {
                                    reason: "Invalid key!".to_string(),
                                }),
                                header: ContentType::JSON,
                            },
                        ));
                    }
                } else {
                    return Outcome::Failure((
                        Status::BadRequest,
                        ApiError {
                            inner: Json(ApiErrorResponse {
                                reason: "Invalid key!".to_string(),
                            }),
                            header: ContentType::JSON,
                        },
                    ));
                }
            }
            None => Outcome::Failure((
                Status::BadRequest,
                ApiError {
                    inner: Json(ApiErrorResponse {
                        reason: "No api key!".to_string(),
                    }),
                    header: ContentType::JSON,
                },
            )),
        }
    }
}

async fn db_connect(db_name: &str) -> Result<Database, mongodb::error::Error> {
    let mut client_options = ClientOptions::parse("mongodb://127.0.0.1:27017").await?;
    client_options.app_name = Some("Express Port".to_string());
    let client = Client::with_options(client_options)?;

    let db = client.database(db_name);
    return Ok(db);
}

#[get("/private")]
async fn private<'a>(user: Result<User, ApiError>) -> Result<String, ApiError> {
    match user {
        Ok(user) => Ok(String::from(format!("Hello, {}!", user.email))),
        Err(err) => Err(err),
    }
}

#[get("/")]
async fn index<'a>() -> String {
    String::from("Hello, world!")
}

#[launch]
async fn rocket() -> rocket::Rocket {
    match db_connect("yitext").await {
        Ok(db) => {
            let jwt_secret = fs::read_to_string("secret.key")
                .expect("You need to have a secret key to launch this server!");
            rocket::ignite()
                .manage(Connection { db: db })
                .manage(JWTSecret { secret: jwt_secret })
                .mount("/", routes![index, private])
        }
        Err(err) => panic!("Error connecting the db! {:?}", err),
    }
}

#[cfg(test)]
mod test {
    use super::rocket;
    use rocket::http::Status;

    #[rocket::async_test]
    async fn hello_world() {
        use rocket::local::asynchronous::Client;

        let client = Client::tracked(rocket().await)
            .await
            .expect("valid rocket instance");
        let req = client.get("/");

        let (r1, r2) = rocket::tokio::join!(req.clone().dispatch(), req.dispatch());
        assert_eq!(r1.status(), r2.status());
        assert_eq!(r1.status(), Status::Ok);

        let (s1, s2) = (r1.into_string().await, r2.into_string().await);
        assert_eq!(s1, s2);
        assert_eq!(s1.unwrap(), "Hello, world!");
    }
}
