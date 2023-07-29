/// This is exactly a port of [h3/examples/server.rs](https://github.com/hyperium/h3/blob/master/examples/server.rs) with `h3-quinn` to the one with `s2n-quic-h3`.
use bytes::{Bytes, BytesMut};
use http::{Request, StatusCode};
use s2n_quic::{provider, Server};
use s2n_quic_h3::h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use s2n_quic_rustls::rustls::{
  self,
  sign::{any_supported_type, CertifiedKey},
};
use std::{
  fs::File,
  io::{self, BufReader, Cursor, Read},
  net::SocketAddr,
  path::PathBuf,
  sync::Arc,
};
use structopt::StructOpt;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
  #[structopt(
    name = "dir",
    short,
    long,
    help = "Root directory of the files to serve. \
                If omitted, server will respond OK."
  )]
  pub root: Option<PathBuf>,

  #[structopt(
    short,
    long,
    default_value = "[::1]:4433",
    help = "What address:port to listen for new connections"
  )]
  pub listen: SocketAddr,

  #[structopt(flatten)]
  pub certs: Certs,
}

#[derive(StructOpt, Debug)]
pub struct Certs {
  #[structopt(
    long,
    short,
    default_value = "./certs/server.crt",
    help = "Certificate for TLS. If present, `--key` is mandatory."
  )]
  pub cert: PathBuf,

  #[structopt(
    long,
    short,
    default_value = "./certs/server.key",
    help = "Private key for the certificate."
  )]
  pub key: PathBuf,
}

static ALPN: &[u8] = b"h3";
static SERVER_NAME: &str = "localhost";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
    .with_writer(std::io::stderr)
    .with_max_level(tracing::Level::DEBUG)
    .init();

  // process cli arguments

  let opt = Opt::from_args();

  let root = if let Some(root) = opt.root {
    if !root.is_dir() {
      return Err(format!("{}: is not a readable directory", root.display()).into());
    } else {
      info!("serving {}", root.display());
      Arc::new(Some(root))
    }
  } else {
    Arc::new(None)
  };

  let Certs { cert, key } = opt.certs;

  // Example using ResolvesServerCertUsingSni
  let mut resolver_global = rustls::server::ResolvesServerCertUsingSni::new();
  let certified_key = read_certs_and_keys(&cert, &key)?;
  if let Err(e) = resolver_global.add(SERVER_NAME, certified_key) {
    error!("{}: Failed to read some certificates and keys {}", SERVER_NAME, e)
  };

  // Example using io with some socket options
  let io = provider::io::tokio::Builder::default()
    .with_receive_address(opt.listen)?
    .with_reuse_port()?
    .build()?;

  let tls = provider::tls::rustls::Server::builder()
    .with_cert_resolver(Arc::new(resolver_global))?
    .with_application_protocols(vec![ALPN].iter())?
    .build()?;

  let mut server = Server::builder().with_tls(tls)?.with_io(io)?.start()?;

  info!("listening on {}", opt.listen);

  // handle incoming connections and requests

  while let Some(new_conn) = server.accept().await {
    info!("new connection established");

    let root = root.clone();

    tokio::spawn(async move {
      let mut h3_conn =
        match s2n_quic_h3::h3::server::Connection::<_, Bytes>::new(s2n_quic_h3::Connection::new(new_conn)).await {
          Ok(v) => v,
          Err(e) => {
            error!("establishing new http/3 connection failed: {}", e);
            return;
          }
        };
      info!("new connection established");

      loop {
        match h3_conn.accept().await {
          Ok(Some((req, stream))) => {
            info!("new request: {:#?}", req);

            let root = root.clone();

            tokio::spawn(async {
              if let Err(e) = handle_request(req, stream, root).await {
                error!("handling request failed: {}", e);
              }
            });
          }

          // indicating no more streams to be received
          Ok(None) => {
            break;
          }

          Err(err) => {
            error!("error on accept {}", err);
            match err.get_error_level() {
              ErrorLevel::ConnectionError => break,
              ErrorLevel::StreamError => continue,
            }
          }
        }
      }
    });
  }

  Ok(())
}

async fn handle_request<T>(
  req: Request<()>,
  mut stream: RequestStream<T, Bytes>,
  serve_root: Arc<Option<PathBuf>>,
) -> Result<(), Box<dyn std::error::Error>>
where
  T: BidiStream<Bytes>,
{
  let (status, to_serve) = match serve_root.as_deref() {
    None => (StatusCode::OK, None),
    Some(_) if req.uri().path().contains("..") => (StatusCode::NOT_FOUND, None),
    Some(root) => {
      let to_serve = root.join(req.uri().path().strip_prefix('/').unwrap_or(""));
      match tokio::fs::File::open(&to_serve).await {
        Ok(file) => (StatusCode::OK, Some(file)),
        Err(e) => {
          error!("failed to open: \"{}\": {}", to_serve.to_string_lossy(), e);
          (StatusCode::NOT_FOUND, None)
        }
      }
    }
  };

  let resp = http::Response::builder().status(status).body(()).unwrap();

  match stream.send_response(resp).await {
    Ok(_) => {
      info!("successfully respond to connection");
    }
    Err(err) => {
      error!("unable to send response to connection peer: {:?}", err);
    }
  }

  if let Some(mut file) = to_serve {
    loop {
      let mut buf = BytesMut::with_capacity(4096 * 10);
      if file.read_buf(&mut buf).await? == 0 {
        break;
      }
      stream.send_data(buf.freeze()).await?;
    }
  }

  Ok(stream.finish().await?)
}

fn read_certs_and_keys(
  cert_path: &PathBuf,
  cert_key_path: &PathBuf,
) -> Result<CertifiedKey, Box<dyn std::error::Error>> {
  let certs: Vec<_> = {
    let certs_path_str = cert_path.display().to_string();
    let mut reader = BufReader::new(File::open(cert_path).map_err(|e| {
      io::Error::new(
        e.kind(),
        format!("Unable to load the certificates [{certs_path_str}]: {e}"),
      )
    })?);
    rustls_pemfile::certs(&mut reader)
      .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Unable to parse the certificates"))?
  }
  .drain(..)
  .map(rustls::Certificate)
  .collect();

  let cert_keys: Vec<_> = {
    let cert_key_path_str = cert_key_path.display().to_string();
    let encoded_keys = {
      let mut encoded_keys = vec![];
      File::open(cert_key_path)
        .map_err(|e| {
          io::Error::new(
            e.kind(),
            format!("Unable to load the certificate keys [{cert_key_path_str}]: {e}"),
          )
        })?
        .read_to_end(&mut encoded_keys)?;
      encoded_keys
    };
    let mut reader = Cursor::new(encoded_keys);
    let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader).map_err(|_| {
      io::Error::new(
        io::ErrorKind::InvalidInput,
        "Unable to parse the certificates private keys (PKCS8)",
      )
    })?;
    reader.set_position(0);
    let mut rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)?;
    let mut keys = pkcs8_keys;
    keys.append(&mut rsa_keys);
    if keys.is_empty() {
      return Err(Box::new(io::Error::new(
        io::ErrorKind::InvalidInput,
        "No private keys found - Make sure that they are in PKCS#8/PEM format",
      )));
    }
    keys.drain(..).map(rustls::PrivateKey).collect()
  };

  let signing_key = cert_keys
    .iter()
    .find_map(|k| {
      if let Ok(sk) = any_supported_type(k) {
        Some(sk)
      } else {
        None
      }
    })
    .ok_or_else(|| {
      io::Error::new(
        io::ErrorKind::InvalidInput,
        "Unable to find a valid certificate and key",
      )
    })?;
  Ok(rustls::sign::CertifiedKey::new(certs.clone(), signing_key))
}
