use clap::{
  crate_authors, crate_description, crate_name, crate_version, App, AppSettings, Arg, ArgGroup,
  ArgMatches, SubCommand,
};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretstream;
use std::convert::TryInto;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use thiserror::Error;

const BORE_VERSION: u32 = 0;
// http://nacl.cr.yp.to/valid.html
const CHUNK_SIZE: usize = 4096;
const MAX_FRAME_SIZE: usize = 8192; // conservative estimate

#[derive(Debug, Error)]
enum Error {
  #[error("Failed to initialize secretstream")]
  InitStream,
  #[error("Failed to initialize sodiumoxide")]
  InitSodiumOxide,
  #[error("File exists: {0}")]
  FileExists(String),
  #[error("Couldn't process filename: {0}")]
  Filename(String),
  #[error("Original filename was `{0}`; cannot decrypt from `{1}`")]
  FilenameMismatch(String, String),
  #[error("Cannot process file of type {0} v{1}")]
  FiletypeMismatch(String, u32),
  #[error("Packet length {0} is larger than max size {1}")]
  PacketTooLong(usize, usize),
  #[error("Key derivation failed")]
  KeyDerivation,
  #[error("Invalid keyfile")]
  InvalidKeyfile,
  #[error("Pushing to secretstream failed")]
  Push,
  #[error("Pulling from secretstream failed")]
  Pull,
  #[error("Finalizing secretstream failed")]
  Finalize,
  #[error("Invalid file header")]
  InvalidHeader,
  #[error(transparent)]
  IO(#[from] std::io::Error),
  #[error(transparent)]
  Persist(#[from] tempfile::PersistError),
  #[error(transparent)]
  Json(#[from] serde_json::Error),
}

fn main() -> Result<(), Error> {
  sodiumoxide::init().map_err(|_| Error::InitSodiumOxide)?;

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
  panic!("no subcommand")
}

// File consists of 1 Header followed by any number of Packets.

#[derive(Debug, Serialize, Deserialize)]
struct Header {
  r#type: String, // constant value
  version: u32,
  stream_header: secretstream::Header,
  pw_salt: Option<pwhash::Salt>, // only present if password was used
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
  Ok(result)
}

// Read exactly n bytes from R
fn read_exact<R: Read>(reader: &mut R, n: usize) -> Result<Vec<u8>, Error> {
  let mut result: Vec<u8> = Vec::with_capacity(n);
  result.resize(n, 0);
  reader.read_exact(&mut result[..])?;
  Ok(result)
}

// read a little-endian u32 length-delimited frame.
// max_size is the maximum acceptable size of a frame
fn read_frame<R: Read>(reader: &mut R, max_size: usize) -> Result<Vec<u8>, Error> {
  let len_bytes = read_exact(reader, std::mem::size_of::<u32>())?;
  let len: usize = u32::from_le_bytes((&len_bytes[..]).try_into().unwrap())
    .try_into()
    .unwrap();
  if len > max_size {
    return Err(Error::PacketTooLong(len, max_size));
  }
  read_exact(reader, len)
}

// frame.len() must fit in u32
fn write_frame<W: Write>(writer: &mut W, frame: Vec<u8>) -> Result<(), Error> {
  writer.write_all(&u32::to_le_bytes(frame.len().try_into().unwrap()))?;
  Ok(writer.write_all(&frame[..])?)
}

fn seal(matches: &ArgMatches) -> Result<(), Error> {
  let (key, pw_salt) = if let Some(key_file) = matches.value_of("key-file") {
    (load_key(key_file)?, None)
  } else if let Some(password_file) = matches.value_of("password-file") {
    let salt = pwhash::gen_salt();
    (key_from_passwd(password_file, salt)?, Some(salt))
  } else {
    panic!("no key or password");
  };

  let (mut enc_stream, stream_header) =
    secretstream::Stream::init_push(&key).map_err(|_| Error::InitStream)?;

  let filename = matches.value_of("input").unwrap();
  let mut input = BufReader::new(fs::File::open(filename)?);

  let final_output_path = format!("{}.bore", filename);
  if fs::metadata(&final_output_path).is_ok() {
    return Err(Error::FileExists(final_output_path));
  }

  let output_file = NamedTempFile::new_in(
    Path::new(filename)
      .parent()
      .ok_or_else(|| Error::Filename(filename.to_string()))?,
  )?;
  let mut output = BufWriter::new(output_file.reopen()?);

  write_frame(
    &mut output,
    serde_json::to_vec(&Header {
      r#type: "bore".to_string(),
      version: BORE_VERSION,
      stream_header,
      pw_salt,
    })?,
  )?;

  let inner_header = serde_json::to_vec(&InnerHeader {
    filename: Path::new(filename)
      .file_name()
      .ok_or_else(|| Error::Filename(filename.to_string()))?
      .to_str()
      .ok_or_else(|| Error::Filename(filename.to_string()))?
      .to_string(),
  })?;

  write_frame(
    &mut output,
    enc_stream
      .push(&inner_header, None, secretstream::Tag::Message)
      .map_err(|_| Error::Push)?,
  )?;

  loop {
    let plaintext = read_n(&mut input, CHUNK_SIZE)?;
    if plaintext.is_empty() {
      break;
    }
    write_frame(
      &mut output,
      enc_stream
        .push(&plaintext, None, secretstream::Tag::Message)
        .map_err(|_| Error::Push)?,
    )?;
  }

  write_frame(
    &mut output,
    enc_stream.finalize(None).map_err(|_| Error::Finalize)?,
  )?;

  output_file.persist(final_output_path)?;

  return Ok(());
}

fn open(matches: &ArgMatches) -> Result<(), Error> {
  let input_filename = matches.value_of("input").unwrap();
  let mut input = BufReader::new(fs::File::open(input_filename)?);

  let header: Header = serde_json::from_slice(&read_frame(&mut input, MAX_FRAME_SIZE)?[..])?;

  if header.r#type != "bore" || header.version != BORE_VERSION {
    return Err(Error::FiletypeMismatch(header.r#type, header.version));
  }

  let key = if let Some(key_file) = matches.value_of("key-file") {
    load_key(key_file)?
  } else if let Some(password_file) = matches.value_of("password-file") {
    let salt = header.pw_salt.ok_or(Error::InvalidHeader)?;
    key_from_passwd(password_file, salt)?
  } else {
    panic!("no key or password");
  };

  let mut dec_stream =
    secretstream::Stream::init_pull(&header.stream_header, &key).map_err(|_| Error::InitStream)?;

  let inner_header: InnerHeader = serde_json::from_slice(
    &dec_stream
      .pull(&read_frame(&mut input, MAX_FRAME_SIZE)?[..], None)
      .map_err(|_| Error::Pull)?
      .0[..],
  )?;

  let input_filepath = Path::new(input_filename);
  let input_name = input_filepath
    .file_name()
    .ok_or_else(|| Error::Filename(input_filename.to_string()))?
    .to_str()
    .ok_or_else(|| Error::Filename(input_filename.to_string()))?;
  if format!("{}.bore", inner_header.filename) != input_name {
    return Err(Error::FilenameMismatch(
      inner_header.filename,
      input_name.to_string(),
    ));
  }

  let final_output_path = input_filepath.with_file_name(&inner_header.filename);
  if fs::metadata(&final_output_path).is_ok() {
    return Err(Error::FileExists(
      final_output_path
        .to_str()
        .unwrap_or(&inner_header.filename)
        .to_string(),
    ));
  }

  let output_file = NamedTempFile::new_in(
    input_filepath
      .parent()
      .ok_or_else(|| Error::Filename(input_filename.to_string()))?,
  )?;
  let mut output = BufWriter::new(output_file.reopen()?);

  while dec_stream.is_not_finalized() {
    output.write_all(
      &dec_stream
        .pull(&read_frame(&mut input, MAX_FRAME_SIZE)?[..], None)
        .map_err(|_| Error::Pull)?
        .0[..],
    )?;
  }

  output_file.persist(final_output_path)?;

  Ok(())
}

fn gen_key(matches: &ArgMatches) -> Result<(), Error> {
  let key = secretstream::gen_key();
  let filename = matches.value_of("output").unwrap();
  let mut file = fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(filename)?;
  file.write_all(key.as_ref())?;
  Ok(())
}

fn load_key(key_file: &str) -> Result<secretstream::Key, Error> {
  let kb = &fs::read(key_file)?;
  let key = secretstream::Key::from_slice(kb).ok_or(Error::InvalidKeyfile)?;
  return Ok(key);
}

fn key_from_passwd(passwd_file: &str, salt: pwhash::Salt) -> Result<secretstream::Key, Error> {
  let mut kb = [0; secretstream::KEYBYTES];
  let passwd = fs::read(passwd_file)?;
  pwhash::derive_key_sensitive(&mut kb, &passwd, &salt).map_err(|_| Error::KeyDerivation)?;

  return Ok(secretstream::Key(kb));
}
