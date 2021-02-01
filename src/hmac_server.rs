use rocket::http;
use rocket::State;

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;

struct Key(Vec<u8>);

/// insecure_compare compare two byte slices for equality
///
///  Solution for problem 7 from set4: <https://cryptopals.com/sets/4/challenges/31>
#[get("/test?<file>&<signature>")]
fn test(k: State<Key>, file: Option<String>, signature: Option<String>) -> http::Status {
    if file == None {
        return http::Status::BadRequest;
    }

    if signature == None {
        return http::Status::BadRequest;
    }

    let path = Path::new("./src/mock_data/").join(file.unwrap());
    let file = File::open(&path);
    if let Err(err) = file {
        println!("{:?}", err);
        return http::Status::InternalServerError;
    }

    let mut content = Vec::new();
    let mut reader = BufReader::new(file.unwrap());
    reader.read_to_end(&mut content).ok();

    let hmac_sha1 = crate::sha1::sha1_hmac(&k.0, &content);

    if insecure_compare(&hmac_sha1, signature.unwrap().as_bytes()) {
        return http::Status::Ok;
    }

    http::Status::InternalServerError
}

/// insecure_compare compare two byte slices for equality
///
///  Solution for problem 7 from set4: <https://cryptopals.com/sets/4/challenges/31>
fn insecure_compare(l: &[u8], r: &[u8]) -> bool {
    if l.len() != r.len() {
        return false;
    }

    for (x, y) in l.iter().zip(r.iter()) {
        if x != y {
            return false;
        }

        // For problem 32 we would need to make som adjustments.
        // to make it work
        std::thread::sleep(std::time::Duration::from_millis(30));
    }

    true
}

pub fn rocket(k: &[u8]) -> rocket::Rocket {
    rocket::ignite()
        .manage(Key(Vec::from(k)))
        .mount("/", routes![test])
}

mod test {
    use super::rocket;
    use rocket::http::Status;
    use rocket::local::Client;

    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_singature() {
        let client = Client::new(rocket(b"YELLOW_SUBMARINE")).expect("valid rocket instance");
        let mut response = client
            .get("/test?file=server_file.txt&signature=8a6d26219f5c4ea40192805b6db4d26bea394df2")
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        let mut response = client
            .get("/test?file=server_file.txt&signature=8a6d26219f5c4ea40192805b6db4d26bea394df1")
            .dispatch();

        assert_eq!(response.status(), Status::InternalServerError);
    }
}
