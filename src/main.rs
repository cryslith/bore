use clap::{
  crate_authors, crate_description, crate_name, crate_version, App, AppSettings, Arg, ArgGroup,
  ArgMatches, SubCommand,
};
use failure::{bail, format_err, Error};
use serde::{Deserialize, Serialize, Serializer};
use serde::ser::SerializeSeq;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretstream;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

const BORE_VERSION: u32 = 0;

fn main() -> Result<(), Error> {
  sodiumoxide::init().map_err(|_| format_err!("Failed to initialize sodiumoxide"))?;

  let matches = App::new(crate_name!())
    .version(crate_version!())
    .author(crate_authors!())
    .about(crate_description!())
    .subcommand(
      SubCommand::with_name("seal")
        .about("encrypt and authenticate the input file")
        .arg(
          Arg::with_name("key-file")
            .short("f")
            .takes_value(true)
            .help("TODO"),
        )
        .arg(
          Arg::with_name("password-file")
            .short("p")
            .takes_value(true)
            .help("TODO"),
        )
        .group(
          ArgGroup::with_name("key")
            .args(&["key-file", "password-file"])
            .required(true),
        )
        .arg(Arg::with_name("input").required(true).help("TODO")),
    )
    .subcommand(
      SubCommand::with_name("open")
        .about("verify and decrypt the input file")
        .arg(
          Arg::with_name("key-file")
            .short("f")
            .takes_value(true)
            .help("TODO"),
        )
        .arg(
          Arg::with_name("password-file")
            .short("p")
            .takes_value(true)
            .help("TODO"),
        )
        .group(
          ArgGroup::with_name("key")
            .args(&["key-file", "password-file"])
            .required(true),
        )
        .arg(Arg::with_name("input").required(true).help("TODO")),
    )
    .subcommand(
      SubCommand::with_name("gen-key")
        .about("generate a random key for use with the --key-file option to seal and open")
        .arg(Arg::with_name("output").required(true).help("TODO")),
    )
    .setting(AppSettings::SubcommandRequired)
    .get_matches();

  if let Some(matches) = matches.subcommand_matches("seal") {
    return seal(matches);
  }
  if let Some(matches) = matches.subcommand_matches("open") {
    return open(matches);
  }
  if let Some(matches) = matches.subcommand_matches("gen-key") {
    return gen_key(matches);
  }
  bail!("No subcommand");
}

// File consists of 1 Header followed by any number of Packets.

#[derive(Debug, Serialize, Deserialize)]
struct Header {
  r#type: String, // constant value
  version: u32,
  stream_header: secretstream::Header,
  pw_salt: Option<pwhash::Salt>, // only present if password was used
}

#[derive(Debug, Serialize, Deserialize)]
struct Packet {
  sealed_data: Vec<u8>,
}

// this is the unsealed contents of the first packet;
// all the rest contain the original file data
#[derive(Debug, Serialize, Deserialize)]
struct InnerHeader {
  filename: String, // original filename
}

// Either read exactly n bytes from R, or until EOF, whichever comes first.
// (I wish this was the semantics of Read::read_exact!)
fn read_n<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, Error> {
  let mut result: Vec<u8> = Vec::with_capacity(n);
  result.resize(n, 0);
  let mut i = 0;
  while i < n {
    let j = reader.read(&mut result[i..])?;
    if j == 0 {
      break;
    }
    i += j;
  }
  result.truncate(i);
  return Ok(result);
}

fn seal(matches: &ArgMatches) -> Result<(), Error> {
  let (key, pw_salt) = if let Some(key_file) = matches.value_of("key-file") {
    (load_key(key_file)?, None)
  } else if let Some(password_file) = matches.value_of("password-file") {
    let salt = pwhash::gen_salt();
    (key_from_passwd(password_file, salt)?, Some(salt))
  } else {
    bail!("Must provide either key file or password file");
  };

  let (mut enc_stream, stream_header) =
    secretstream::Stream::init_push(&key).map_err(|_| format_err!("Failed to initialize stream"))?;

  let filename = matches
    .value_of("input")
    .ok_or_else(|| format_err!("No input filename"))?;
  let mut input = BufReader::new(fs::File::open(filename)?);
  let output = BufWriter::new(
    fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(format!("{}.bore", filename))?,
  );
  let mut ser = serde_cbor::Serializer::new(serde_cbor::ser::IoWrite::new(output));

  Header {
    r#type: "bore".to_string(),
    version: BORE_VERSION,
    stream_header,
    pw_salt,
  }.serialize(&mut ser)?;

  let mut seq = ser.serialize_seq(None)?;

  let inner_header = serde_cbor::to_vec(&InnerHeader {
    filename: filename.to_string(),
  })?;

  seq.serialize_element(
    &Packet {
      sealed_data: enc_stream
        .push(&inner_header, None, secretstream::Tag::Message)
        .map_err(|_| format_err!("Pushing inner header failed"))?,
    },
  )?;

  let packet_size = 8192;

  loop {
    let plaintext = read_n(&mut input, packet_size)?;
    if plaintext.is_empty() {
      break;
    }
    seq.serialize_element(
      &Packet {
        sealed_data: enc_stream
          .push(&plaintext, None, secretstream::Tag::Message)
          .map_err(|_| format_err!("Pushing message failed"))?,
      },
    )?;
  }

  seq.serialize_element(
    &Packet {
      sealed_data: enc_stream
        .finalize(None)
        .map_err(|_| format_err!("Finalizing failed"))?,
    },
  )?;

  seq.end()?;

  return Ok(());
}

// Note that there's no way to do this atomically.
fn rename_noclobber<P1: AsRef<Path>, P2: AsRef<Path> + Copy>(p1: P1, p2: P2) -> Result<(), Error> {
  if fs::metadata(p2).is_ok() {
    bail!("File exists");
  }
  fs::rename(p1, p2)?;
  return Ok(());
}

fn open(matches: &ArgMatches) -> Result<(), Error> {
  // if (fs::metadata(filename).is_ok()) {
  //   bail!("File exists");
  // }

  unimplemented!();
}

fn gen_key(matches: &ArgMatches) -> Result<(), Error> {
  let key = secretstream::gen_key();
  let filename = matches
    .value_of("output")
    .ok_or_else(|| format_err!("Must specify filename"))?;
  let mut file = fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(filename)?;
  file.write_all(key.as_ref())?;
  Ok(())
}

fn load_key(key_file: &str) -> Result<secretstream::Key, Error> {
  let kb = &fs::read(key_file)?;
  let key = secretstream::Key::from_slice(kb).ok_or_else(|| format_err!("Invalid keyfile"))?;
  return Ok(key);
}

fn key_from_passwd(passwd_file: &str, salt: pwhash::Salt) -> Result<secretstream::Key, Error> {
  let mut kb = [0; secretstream::KEYBYTES];
  let passwd = fs::read(passwd_file)?;
  pwhash::derive_key_sensitive(&mut kb, &passwd, &salt)
    .map_err(|_| format_err!("Key derivation failed"))?;

  return Ok(secretstream::Key(kb));
}
