/// This is exactly a port of [h3/examples/server.rs](https://github.com/hyperium/h3/blob/master/examples/server.rs) with `h3-quinn` to the one with `s2n-quic-h3`.
use bytes::{Bytes, BytesMut};
use http::{Request, StatusCode};
use s2n_quic::{provider, Server};
use s2n_quic_h3::h3::{error::ErrorLevel, quic::BidiStream, server::RequestStream};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use structopt::StructOpt;
use tokio::{fs::File, io::AsyncReadExt};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
    .with_writer(std::io::stderr)
    .with_max_level(tracing::Level::INFO)
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

  let tls = provider::tls::rustls::Server::builder()
    .with_certificate(cert.as_path(), key.as_path())?
    .with_application_protocols(vec![ALPN].iter())?
    .build()?;

  let mut server = Server::builder().with_tls(tls)?.with_io(opt.listen)?.start()?;

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
      match File::open(&to_serve).await {
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
