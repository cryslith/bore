use clap::{
  crate_authors, crate_description, crate_name, crate_version, App, AppSettings, Arg, ArgGroup,
  ArgMatches, SubCommand,
};
use failure::{bail, format_err, Error};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretstream;
use std::convert::TryInto;
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use tempfile::NamedTempFile;

const BORE_VERSION: u32 = 0;
// http://nacl.cr.yp.to/valid.html
const CHUNK_SIZE: usize = 4096;
const MAX_FRAME_SIZE: usize = 8192; // conservative estimate

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
  let len: usize = u32::from_le_bytes((&len_bytes[..]).try_into().unwrap()).try_into()?;
  if len > max_size {
    bail!("packet length {} is larger than max size {}", len, max_size,);
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
    (
      load_key(key_file).map_err(|e| format_err!("Error loading key file: {}", e))?,
      None,
    )
  } else if let Some(password_file) = matches.value_of("password-file") {
    let salt = pwhash::gen_salt();
    (
      key_from_passwd(password_file, salt)
        .map_err(|e| format_err!("Error generating key from password: {}", e))?,
      Some(salt),
    )
  } else {
    bail!("Must provide either key file or password file");
  };

  let (mut enc_stream, stream_header) = secretstream::Stream::init_push(&key)
    .map_err(|_| format_err!("Failed to initialize stream"))?;

  let filename = matches
    .value_of("input")
    .ok_or_else(|| format_err!("No input filename"))?;
  let mut input = BufReader::new(fs::File::open(filename)?);

  let final_output_path = format!("{}.bore", filename);
  if fs::metadata(&final_output_path).is_ok() {
    bail!("File exists: {}", final_output_path);
  }

  let output_file = NamedTempFile::new_in(
    Path::new(filename)
      .parent()
      .ok_or_else(|| format_err!("Error extracting parent from {}", filename))?,
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
      .ok_or_else(|| format_err!("Error extracting filename from {}", filename))?
      .to_str()
      .ok_or_else(|| format_err!("Filename must be valid Unicode"))?
      .to_string(),
  })?;

  write_frame(
    &mut output,
    enc_stream
      .push(&inner_header, None, secretstream::Tag::Message)
      .map_err(|_| format_err!("Pushing inner header failed"))?,
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
        .map_err(|_| format_err!("Pushing message failed"))?,
    )?;
  }

  write_frame(
    &mut output,
    enc_stream
      .finalize(None)
      .map_err(|_| format_err!("Finalizing failed"))?,
  )?;

  output_file.persist(final_output_path)?;

  return Ok(());
}

fn open(matches: &ArgMatches) -> Result<(), Error> {
  let input_filename = matches
    .value_of("input")
    .ok_or_else(|| format_err!("No input filename"))?;
  let mut input = BufReader::new(
    fs::File::open(input_filename).map_err(|e| format_err!("Error opening input file: {}", e))?,
  );

  let header: Header = serde_json::from_slice(&read_frame(&mut input, MAX_FRAME_SIZE)?[..])?;

  if header.r#type != "bore" || header.version != BORE_VERSION {
    bail!(
      "Expected file type bore v{}, got {} v{}",
      BORE_VERSION,
      header.r#type,
      header.version,
    );
  }

  let key = if let Some(key_file) = matches.value_of("key-file") {
    load_key(key_file).map_err(|e| format_err!("Error loading key file: {}", e))?
  } else if let Some(password_file) = matches.value_of("password-file") {
    let salt = header
      .pw_salt
      .ok_or_else(|| format_err!("Password salt not present in file header."))?;
    key_from_passwd(password_file, salt)
      .map_err(|e| format_err!("Error generating key from password: {}", e))?
  } else {
    bail!("Must provide either key file or password file");
  };

  let mut dec_stream = secretstream::Stream::init_pull(&header.stream_header, &key)
    .map_err(|_| format_err!("Failed to initialize stream"))?;

  let inner_header: InnerHeader = serde_json::from_slice(
    &dec_stream
      .pull(&read_frame(&mut input, MAX_FRAME_SIZE)?[..], None)
      .map_err(|_| format_err!("Pulling inner header failed"))?
      .0[..],
  )?;

  let input_filepath = Path::new(input_filename);
  let input_name = input_filepath
    .file_name()
    .ok_or_else(|| format_err!("Error extracting filename from {}", input_filename))?
    .to_str()
    .ok_or_else(|| format_err!("Filename must be valid Unicode"))?;
  if format!("{}.bore", inner_header.filename) != input_name {
    bail!(
      "Original filename was `{}`; cannot decrypt from `{}`",
      inner_header.filename,
      input_name,
    );
  }

  let final_output_path = input_filepath.with_file_name(&inner_header.filename);
  if fs::metadata(&final_output_path).is_ok() {
    bail!(
      "File exists: {}",
      final_output_path.to_str().unwrap_or(&inner_header.filename)
    );
  }

  let output_file = NamedTempFile::new_in(
    input_filepath
      .parent()
      .ok_or_else(|| format_err!("Error extracting parent from {}", input_filename))?,
  )?;
  let mut output = BufWriter::new(output_file.reopen()?);

  while dec_stream.is_not_finalized() {
    output.write_all(
      &dec_stream
        .pull(&read_frame(&mut input, MAX_FRAME_SIZE)?[..], None)
        .map_err(|_| format_err!("Pulling message failed"))?
        .0[..],
    )?;
  }

  output_file.persist(final_output_path)?;

  Ok(())
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
