use futures::future;
use s2n_quic::{client::Connect, provider, Client};
use s2n_quic_rustls as rustls;
use std::path::PathBuf;
use structopt::StructOpt;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};

static ALPN: &[u8] = b"h3";

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
  #[structopt(
    long,
    short,
    default_value = "certs/ca.crt",
    help = "Certificate of CA who issues the server certificate"
  )]
  pub ca: PathBuf,

  #[structopt(name = "keylogfile", long)]
  pub key_log_file: bool,

  #[structopt()]
  pub uri: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  tracing_subscriber::fmt()
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
    .with_writer(std::io::stderr)
    .with_max_level(tracing::Level::INFO)
    .init();

  let opt = Opt::from_args();

  // DNS lookup

  let uri = opt.uri.parse::<http::Uri>()?;

  if uri.scheme() != Some(&http::uri::Scheme::HTTPS) {
    Err("uri scheme must be 'https'")?;
  }

  let auth = uri.authority().ok_or("uri must have a host")?.clone();

  let port = auth.port_u16().unwrap_or(443);

  // In my env, ipv6 doesn't work properly.
  let addr = tokio::net::lookup_host((auth.host(), port))
    .await?
    .find(|v| v.is_ipv4())
    .ok_or("dns found no addresses")?;

  info!("DNS lookup for {:?}: {:?}", uri, addr);

  // create s2n-quic client

  // load CA certificates stored in the system
  let mut root_certs = match rustls_native_certs::load_native_certs() {
    Ok(certs) => certs.into_iter().map(|v| rustls::Certificate(v.0)).collect(),
    Err(e) => {
      error!("couldn't load any default trust roots: {}", e);
      Vec::new()
    }
  };

  // load certificate of CA who issues the server certificate
  // NOTE that this should be used for dev only
  root_certs.push(rustls::Certificate(std::fs::read(opt.ca)?));

  let mut tls = provider::tls::rustls::Client::builder().with_application_protocols(vec![ALPN].iter())?;
  tls = root_certs
    .into_iter()
    .fold(tls, |acc, cert| acc.with_certificate(cert.0).unwrap());
  // optional debugging support
  tls = if opt.key_log_file {
    // Write all Keys to a file if SSLKEYLOGFILE is set
    // WARNING, we enable this for the example, you should think carefully about enabling in your own code
    tls.with_key_logging()?
  } else {
    tls
  };
  let tls = tls.build()?;

  let client = Client::builder().with_tls(tls)?.with_io("0.0.0.0:0")?.start()?;
  let connect = Connect::new(addr).with_server_name(auth.host());
  let mut connection = client.connect(connect).await?;

  info!("QUIC connection established");

  // ensure the connection doesn't time out with inactivity
  connection.keep_alive(true)?;

  // create h3 client

  // h3 is designed to work with different QUIC implementations via
  // a generic interface, that is, the [`quic::Connection`] trait.
  let quic_conn = s2n_quic_h3::Connection::new(connection);

  let (mut driver, mut send_request) = s2n_quic_h3::h3::client::new(quic_conn).await?;

  let drive = async move {
    future::poll_fn(|cx| driver.poll_close(cx)).await?;
    Ok::<(), Box<dyn std::error::Error>>(())
  };

  // In the following block, we want to take ownership of `send_request`:
  // the connection will be closed only when all `SendRequest`s instances
  // are dropped.
  //
  //             So we "move" it.
  //                  vvvv
  let request = async move {
    info!("sending request ...");

    let req = http::Request::builder().uri(uri).body(())?;

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = send_request.send_request(req).await?;

    // finish on the sending side
    stream.finish().await?;

    info!("receiving response ...");

    let resp = stream.recv_response().await?;

    info!("response: {:?} {}", resp.version(), resp.status());
    info!("headers: {:#?}", resp.headers());

    // `recv_data()` must be called after `recv_response()` for
    // receiving potential response body
    while let Some(mut chunk) = stream.recv_data().await? {
      let mut out = tokio::io::stdout();
      out.write_all_buf(&mut chunk).await?;
      out.flush().await?;
    }

    Ok::<_, Box<dyn std::error::Error>>(())
  };

  let (req_res, drive_res) = tokio::join!(request, drive);
  req_res?;
  drive_res?;

  // wait for the connection to be closed before exiting

  Ok(())
}
