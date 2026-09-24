//! Chained-dial contract: a node with `detour` reaches its own server through
//! the front node, generation-pinned, and fails closed without a generation.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use honk_config::node::Node;
use honk_outbound::chain;
use honk_outbound::proxy::{AsyncReadWrite, ProxyRegistry};
use honk_outbound::runtime::OutboundRuntimeRegistry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn socks5_node(name: &str, port: u16) -> Node {
    Node::from_share_link(&format!("socks5://127.0.0.1:{port}#{name}")).unwrap()
}

fn chained_node(name: &str, port: u16, front: &str) -> Node {
    let mut node = socks5_node(name, port);
    node.detour = Some(front.to_string());
    node.id = node.derive_id();
    node
}

/// A target server that echoes every byte back.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// Minimal RFC 1928 no-auth CONNECT server that records requested targets.
async fn socks5_server() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let recorded = Arc::clone(&recorded);
            tokio::spawn(async move {
                let _ = serve_socks5(client, recorded).await;
            });
        }
    });
    (addr, seen)
}

async fn serve_socks5(mut client: TcpStream, seen: Arc<Mutex<Vec<String>>>) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    client.read_exact(&mut methods).await?;
    client.write_all(&[0x05, 0x00]).await?;

    let mut request = [0u8; 4];
    client.read_exact(&mut request).await?;
    let host = match request[3] {
        0x01 => {
            let mut raw = [0u8; 4];
            client.read_exact(&mut raw).await?;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        0x04 => {
            let mut raw = [0u8; 16];
            client.read_exact(&mut raw).await?;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            client.read_exact(&mut raw).await?;
            String::from_utf8_lossy(&raw).into_owned()
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    seen.lock().unwrap().push(format!("{host}:{port}"));

    let mut upstream = TcpStream::connect((host.as_str(), port)).await?;
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    Ok(())
}

#[tokio::test]
async fn chained_dial_reaches_the_exit_through_the_front() {
    let echo = echo_server().await;
    let (exit_addr, exit_seen) = socks5_server().await;
    let (front_addr, front_seen) = socks5_server().await;

    let front = socks5_node("front", front_addr.port());
    let exit = chained_node("exit", exit_addr.port(), "front");
    let generation = Arc::new(
        OutboundRuntimeRegistry::build(&[front, exit.clone()]).expect("valid runtime generation"),
    );
    let registry = ProxyRegistry::default_resolver().unwrap();

    let proxy = registry
        .dial_runtime(generation, exit.id, echo, None, Duration::from_secs(5))
        .await
        .expect("chained dial must succeed");

    let mut stream: Box<dyn AsyncReadWrite> = proxy.stream;
    stream.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");

    // The front hop must have been asked for the exit server, and the exit
    // server for the real target — direct dialing would show neither.
    assert!(
        front_seen.lock().unwrap().contains(&exit_addr.to_string()),
        "front must relay to the exit server: {:?}",
        front_seen.lock().unwrap()
    );
    assert!(
        exit_seen.lock().unwrap().contains(&echo.to_string()),
        "exit must be asked for the target: {:?}",
        exit_seen.lock().unwrap()
    );
}

#[tokio::test]
async fn chained_dial_without_a_generation_fails_closed() {
    let exit = chained_node("exit", 1, "front");
    let error = chain::connect_server(&exit, Duration::from_secs(1))
        .await
        .expect_err("a chained dial outside a runtime generation must not connect");
    assert!(error.to_string().contains("runtime generation"), "{error}");
}

#[tokio::test]
async fn chained_udp_dial_without_a_generation_fails_closed() {
    let exit = chained_node("exit", 1, "front");
    let error = match chain::connect_udp_via_front(&exit, Duration::from_secs(1)).await {
        Ok(_) => panic!("a chained UDP dial outside a runtime generation must not connect"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("runtime generation"), "{error}");
}

/// The dae `exit -> front` surface produces a tagged exit plus an internal
/// front, and that pair dials through the front end to end.
#[tokio::test]
async fn dae_arrow_chain_dials_through_the_front() {
    let echo = echo_server().await;
    let (exit_addr, exit_seen) = socks5_server().await;
    let (front_addr, front_seen) = socks5_server().await;

    let chain = Node::from_share_link_chain(&format!(
        "socks5://127.0.0.1:{}#exit -> socks5://127.0.0.1:{}#front",
        exit_addr.port(),
        front_addr.port()
    ))
    .expect("dae chain parses");
    assert_eq!(chain.len(), 2);
    assert!(!chain[0].internal && chain[1].internal);
    assert_eq!(chain[0].detour.as_deref(), Some(chain[1].name.as_str()));

    let generation = Arc::new(OutboundRuntimeRegistry::build(&chain).expect("valid generation"));
    let registry = ProxyRegistry::default_resolver().unwrap();
    let proxy = registry
        .dial_runtime(generation, chain[0].id, echo, None, Duration::from_secs(5))
        .await
        .expect("dae-chained dial must succeed");

    let mut stream: Box<dyn AsyncReadWrite> = proxy.stream;
    stream.write_all(b"pong").await.unwrap();
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    assert!(front_seen.lock().unwrap().contains(&exit_addr.to_string()));
    assert!(exit_seen.lock().unwrap().contains(&echo.to_string()));
}

/// A server that accepts and discards, for exits whose handshake needs no
/// reply (Shadowsocks' request is write-only at dial time).
async fn tcp_sink_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn shadowsocks_exit_dials_through_the_front() {
    let exit_addr = tcp_sink_server().await;
    let (front_addr, front_seen) = socks5_server().await;
    let front = socks5_node("front", front_addr.port());
    let mut exit = Node::from_share_link(&format!(
        "ss://YWVzLTI1Ni1nY206cGFzcw@127.0.0.1:{}#ss",
        exit_addr.port()
    ))
    .unwrap();
    exit.detour = Some("front".into());
    exit.id = exit.derive_id();

    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit.clone()]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let dial = registry.dial_runtime(generation, exit.id, target, None, Duration::from_secs(5));
    tokio::time::timeout(Duration::from_secs(10), dial)
        .await
        .expect("Shadowsocks chained dial must not hang")
        .expect("Shadowsocks exit must chain through the front");
    assert!(
        front_seen.lock().unwrap().contains(&exit_addr.to_string()),
        "front must relay to the SS server: {:?}",
        front_seen.lock().unwrap()
    );
}

#[tokio::test]
async fn direct_front_is_a_direct_dial() {
    let echo = echo_server().await;
    let (exit_addr, exit_seen) = socks5_server().await;
    let direct = honk_config::config::Config::builtin_direct_node();
    let exit = chained_node("exit", exit_addr.port(), "direct");
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[direct, exit.clone()]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();

    let proxy = registry
        .dial_runtime(generation, exit.id, echo, None, Duration::from_secs(5))
        .await
        .expect("a direct front dials the exit server directly");
    let mut stream: Box<dyn AsyncReadWrite> = proxy.stream;
    stream.write_all(b"direct").await.unwrap();
    let mut buf = [0u8; 6];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"direct");
    assert!(exit_seen.lock().unwrap().contains(&echo.to_string()));
}

#[tokio::test]
async fn block_front_fails_the_server_connection() {
    let block = honk_config::config::Config::builtin_block_node();
    let exit = chained_node("exit", 1, "block");
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[block, exit.clone()]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();
    let error = registry
        .dial_runtime(
            generation,
            exit.id,
            "127.0.0.1:9".parse().unwrap(),
            None,
            Duration::from_secs(1),
        )
        .await
        .expect_err("a block front must not connect");
    assert!(!error.to_string().is_empty());
}

struct FrontGroupResolver {
    leaf: Node,
}

impl chain::GroupFrontResolver for FrontGroupResolver {
    fn resolve_tcp_leaf(&self, group: &str) -> Option<Node> {
        (group == "front-group").then(|| self.leaf.clone())
    }
}

#[tokio::test]
async fn group_front_resolves_to_its_leaf() {
    let echo = echo_server().await;
    let (exit_addr, _exit_seen) = socks5_server().await;
    let (front_addr, front_seen) = socks5_server().await;
    let front = socks5_node("front", front_addr.port());
    chain::install_group_resolver(Arc::new(FrontGroupResolver {
        leaf: front.clone(),
    }));
    let exit = chained_node("exit", exit_addr.port(), "front-group");
    let generation = Arc::new(OutboundRuntimeRegistry::build(&[front, exit.clone()]).unwrap());
    let registry = ProxyRegistry::default_resolver().unwrap();

    registry
        .dial_runtime(generation, exit.id, echo, None, Duration::from_secs(5))
        .await
        .expect("a group front must resolve its leaf");
    assert!(front_seen.lock().unwrap().contains(&exit_addr.to_string()));
}
