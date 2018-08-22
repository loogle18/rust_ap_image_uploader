extern crate s3;
extern crate clap;
extern crate mime_guess;
extern crate scoped_threadpool;
extern crate glob;

use std::{str, env};
use std::io::prelude::*;
use std::fs::{self, File};
use std::path::Path;
use glob::glob;
use scoped_threadpool::Pool;
use mime_guess::guess_mime_type;
use s3::bucket::Bucket;
use s3::credentials::Credentials;
use clap::{Arg, App, ArgMatches};

fn check_end_exit(condition: bool, message: &str) {
    if condition {
        eprintln!("{:?}", message.to_string());
        std::process::exit(1);
    }
}

fn get_matches<'a>() -> ArgMatches<'a> {
    return App::new("DO image uploader")
                    .version("1.0")
                    .author("Sviat M. <sviat.minato@gmail.com>")
                    .about("Upload images to DO space")
                    .arg(Arg::with_name("space_name")
                         .short("n")
                         .long("space_name")
                         .help("Name of the DO space")
                         .takes_value(true)
                         .required(true))
                    .arg(Arg::with_name("path")
                         .short("p")
                         .long("path")
                         .help("Path to images folder.")
                         .takes_value(true)
                         .required(true))
                    .arg(Arg::with_name("remove_after")
                         .short("r")
                         .long("remove_after")
                         .help("Remove files after upload")
                         .default_value("false")
                         .possible_values(&["true", "false"]))
                    .get_matches();
}

fn get_space(space_name: &str) -> Bucket {
    let access_key = env::var("DO_ACCESS_KEY_ID").ok();
    let secret_key = env::var("DO_SECRET_ACCESS_KEY").ok();

    check_end_exit(access_key.is_none() || secret_key.is_none(), "DO_ACCESS_KEY_ID or DO_SECRET_ACCESS_KEY is missing");

    let credentials = Credentials::new(access_key, secret_key, None, Some("default".to_string()));
    let region = "nyc3".parse().unwrap();

    return Bucket::new(space_name, region, credentials);
}

fn upload_files_from<'a>(path: &Path, remove_after: bool, space: &'a Bucket) {
    let mut pool = Pool::new(32);

    pool.scoped(|scoped| {
        for filepath in glob(format!("{}/**/*", &path.to_str().unwrap()).as_str()).unwrap().filter_map(Result::ok) {
            let mime_type = guess_mime_type(&filepath).to_string();
            if mime_type.contains("image") {
                let mut new_space = space.clone();
                scoped.execute(move || {
                    upload_file(&filepath, mime_type.as_str(), remove_after, &mut new_space);
                });
            }
        }
    });
}

fn upload_file(path: &Path, mime_type: &str, remove_after: bool, space: &mut Bucket) {
    let filename = path.file_name().unwrap().to_str().unwrap();
    let foldername = path.parent().unwrap().file_name().unwrap().to_str().unwrap();
    let key = format!("_{}/{}", foldername, filename);
    let mut file = File::open(path).expect("Unable to read file");
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).expect(format!("Unable to read file {}", filename).as_str());
    space.add_header("x-amz-acl", "public-read");
    space.put(key.as_str(), &buffer.as_slice(), mime_type).expect(format!("Unable to upload file {}", filename).as_str());

    println!("_{}/{}", foldername, filename);

    if remove_after {
        fs::remove_file(path).expect(format!("Unable to delete file {}", filename).as_str());
    }
}

fn main() {
    let matches = get_matches();
    let path = Path::new(matches.value_of("path").unwrap());
    let space_name = matches.value_of("space_name").unwrap();
    let remove_after = matches.value_of("remove_after").unwrap().eq("true");
    check_end_exit(!path.exists(), "Path is invalid");
    upload_files_from(path, remove_after, &get_space(space_name));

    println!("Done!");
}
