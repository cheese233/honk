//! Outbound chaining ("detour"): a node reaches its own server through a
//! front node instead of a direct connection. TCP outbounds use
//! [`connect_server`]; QUIC outbounds use [`connect_udp_via_front`], whose
//! datagrams ride the front's framed UDP transport.
//!
//! `honk-config` owns the declaration (`Node.detour` names the front node).
//! This module owns resolution: the front is looked up by name inside the
//! immutable runtime generation the current dial was pinned to, so a chained
//! hop can never cross a reload boundary or build session state outside
//! generation ownership. A dial with no generation in scope fails closed —
//! there is deliberately no stateless fallback that would bypass either the
//! generation or the dial-admission budget.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use honk_config::node::Node;
use tokio::net::TcpStream;

use crate::proxy::{AsyncReadWrite, ProxyRegistry, ProxyStream};
use crate::runtime::OutboundRuntimeRegistry;

tokio::task_local! {
    /// Generation captured by the dial that is currently running. Set by
    /// every entry point that invokes a handler, so `maybe_tls_wrap_concrete`
    /// and the SOCKS5 dial can resolve a front hop without a process global.
    static DIAL_GENERATION: Arc<OutboundRuntimeRegistry>;
    /// Exits already entered on the current chain, so an imported cycle fails
    /// closed at dial time instead of recursing without bound.
    static CHAIN_PATH: Vec<uuid::Uuid>;
}

/// A chain longer than this is refused: operator configuration rejects
/// cycles, but subscription-imported chains are only checked here.
const MAX_CHAIN_HOPS: usize = 16;

/// Budget for dialing a front hop when a QUIC client is built, which has no
/// per-dial timeout of its own.
pub const CHAIN_QUIC_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

static REGISTRY: std::sync::OnceLock<Arc<ProxyRegistry>> = std::sync::OnceLock::new();

/// Install the process's protocol registry. Idempotent; honk-core installs
/// the same `default_resolver()` table the engine dispatches through.
pub fn install_registry(registry: Arc<ProxyRegistry>) {
    let _ = REGISTRY.set(registry);
}

fn registry() -> anyhow::Result<Arc<ProxyRegistry>> {
    if let Some(registry) = REGISTRY.get() {
        return Ok(Arc::clone(registry));
    }
    let registry = Arc::new(ProxyRegistry::default_resolver()?);
    Ok(Arc::clone(REGISTRY.get_or_init(|| registry)))
}

/// Run `future` with the dial's generation visible to nested chained dials.
pub async fn with_dial_generation<F>(
    generation: Arc<OutboundRuntimeRegistry>,
    future: F,
) -> F::Output
where
    F: std::future::Future,
{
    DIAL_GENERATION.scope(generation, future).await
}

fn current_dial_generation() -> Option<Arc<OutboundRuntimeRegistry>> {
    DIAL_GENERATION.try_with(Arc::clone).ok()
}

async fn with_chain_path<F>(path: Vec<uuid::Uuid>, future: F) -> F::Output
where
    F: std::future::Future,
{
    CHAIN_PATH.scope(path, future).await
}

/// Whether this node must reach its server through a front hop.
pub fn is_chained(node: &Node) -> bool {
    node.detour.is_some()
}

/// A connected stream to a node's own server, before its protocol handshake.
///
/// Direct dials stay a concrete [`TcpStream`] so transport telemetry
/// (`ObservedTcp`, TCP pressure) and the pool behave exactly as before; a
/// chained dial yields the front's tunneled stream instead.
#[derive(Debug)]
pub enum ServerStream {
    Direct(TcpStream),
    DialProxy(Box<dyn AsyncReadWrite>),
}

/// Connect to `node`'s own server endpoint, through its dial-proxy front when
/// it declares one. This is the single server-connect every TCP outbound uses.
pub async fn connect_server(
    node: &Node,
    connect_timeout: Duration,
) -> anyhow::Result<ServerStream> {
    if node.detour.is_none() {
        let addr = format!("{}:{}", node.host(), node.port);
        return Ok(ServerStream::Direct(
            crate::util::connect_outbound(&addr, connect_timeout).await?,
        ));
    }
    let front_name = node
        .detour
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("node '{}' has no detour", node.name))?;
    let generation = current_dial_generation().ok_or_else(|| {
        anyhow::anyhow!(
            "node '{}' needs detour '{front_name}' but no runtime generation is in scope",
            node.name
        )
    })?;
    let front_id = resolve_front(&generation, front_name)?;
    let (target, domain) = resolve_target(node.host(), node.port).await?;
    let mut path = CHAIN_PATH.try_with(|path| path.clone()).unwrap_or_default();
    if path.contains(&node.id) {
        anyhow::bail!("detour chain for '{}' contains a cycle", node.name);
    }
    if path.len() >= MAX_CHAIN_HOPS {
        anyhow::bail!("detour chain exceeds {MAX_CHAIN_HOPS} hops");
    }
    path.push(node.id);
    let proxy: ProxyStream = with_chain_path(path, async {
        registry()?
            .dial_runtime(
                generation,
                front_id,
                target,
                domain.as_deref(),
                connect_timeout,
            )
            .await
    })
    .await?;
    Ok(ServerStream::DialProxy(proxy.stream))
}

/// Resolve the front node's stable id inside `generation`.
///
/// A declared node wins by name (including the built-ins `direct`/`block`, so
/// `direct` means a direct dial and `block` fails the server connection). A
/// name that is not a node is resolved as a group through the installed
/// [`GroupFrontResolver`], whose current TCP leaf must be in this generation.
fn resolve_front(
    generation: &Arc<OutboundRuntimeRegistry>,
    front_name: &str,
) -> anyhow::Result<uuid::Uuid> {
    let mut matches = generation
        .values()
        .filter(|runtime| runtime.node.name == front_name);
    if let Some(front) = matches.next() {
        if matches.next().is_some() {
            anyhow::bail!("detour target '{front_name}' is ambiguous (duplicate node name)");
        }
        return Ok(front.node.id);
    }
    if let Some(leaf) = group_front(front_name) {
        return generation
            .get(&leaf.id)
            .map(|runtime| runtime.node.id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "detour group '{front_name}' selected a node outside the current runtime generation"
                )
            });
    }
    anyhow::bail!("detour target '{front_name}' is not a declared node or group")
}

/// Current TCP leaf of a named group. Implemented by the control plane, which
/// owns the group manager; the chain module must not read group state itself.
pub trait GroupFrontResolver: Send + Sync + 'static {
    fn resolve_tcp_leaf(&self, group: &str) -> Option<Node>;
}

static GROUP_RESOLVER: std::sync::RwLock<Option<Arc<dyn GroupFrontResolver>>> =
    std::sync::RwLock::new(None);

/// Install (or replace) the process-wide group front resolver.
pub fn install_group_resolver(resolver: Arc<dyn GroupFrontResolver>) {
    *GROUP_RESOLVER
        .write()
        .expect("group front resolver lock poisoned") = Some(resolver);
}

fn group_front(name: &str) -> Option<Node> {
    GROUP_RESOLVER
        .read()
        .expect("group front resolver lock poisoned")
        .as_ref()
        .and_then(|resolver| resolver.resolve_tcp_leaf(name))
}

/// Dial `node`'s own server over a framed UDP transport through its front hop.
///
/// QUIC outbounds use this because their server connection is UDP, not a
/// stream: the front must itself be a UDP-capable proxy. The chain path and
/// cycle guards are shared with [`connect_server`].
pub async fn connect_udp_via_front(
    node: &Node,
    connect_timeout: Duration,
) -> anyhow::Result<Arc<dyn crate::proxy::PacketTransport>> {
    let front_name = node
        .detour
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("node '{}' has no detour", node.name))?;
    let generation = current_dial_generation().ok_or_else(|| {
        anyhow::anyhow!(
            "node '{}' needs detour '{front_name}' but no runtime generation is in scope",
            node.name
        )
    })?;
    let front_id = resolve_front(&generation, front_name)?;
    let (target, domain) = resolve_target(node.host(), node.port).await?;
    let mut path = CHAIN_PATH.try_with(|path| path.clone()).unwrap_or_default();
    if path.contains(&node.id) {
        anyhow::bail!("detour chain for '{}' contains a cycle", node.name);
    }
    if path.len() >= MAX_CHAIN_HOPS {
        anyhow::bail!("detour chain exceeds {MAX_CHAIN_HOPS} hops");
    }
    path.push(node.id);
    let registry = registry()?;
    with_chain_path(path, async {
        registry
            .dial_udp_transport_runtime(
                generation,
                front_id,
                target,
                domain.as_deref(),
                connect_timeout,
            )
            .await
    })
    .await
}

/// Build the quinn endpoint a chained QUIC outbound runs on: its datagrams
/// ride the front's framed UDP transport, with an optional per-datagram
/// transform (hysteria2 salamander) applied above the tunnel. Returns the
/// endpoint owner, which the caller must keep alive, and the pinned peer.
pub async fn connect_quic_via_front(
    node: &Node,
    connect_timeout: Duration,
    obfs: Option<Arc<[u8]>>,
) -> anyhow::Result<(Arc<crate::quic::PacketTransportEndpoint>, SocketAddr)> {
    let transport = connect_udp_via_front(node, connect_timeout).await?;
    let remote = transport.relay_addr();
    let endpoint =
        crate::quic::packet_transport_endpoint_with_obfs(transport, remote, obfs, false)?;
    Ok((Arc::new(endpoint), remote))
}

/// Resolve the exit server's endpoint. A hostname is handed to the front hop
/// as a domain so it resolves on the far side; the local numeric address is
/// only a fallback for handlers that need one.
async fn resolve_target(host: &str, port: u16) -> anyhow::Result<(SocketAddr, Option<String>)> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok((SocketAddr::new(ip, port), None));
    }
    let addr = crate::bootstrap::resolve(host)
        .await?
        .into_iter()
        .next()
        .map(|ip| SocketAddr::new(ip, port))
        .ok_or_else(|| anyhow::anyhow!("no address resolved for '{host}:{port}'"))?;
    Ok((addr, Some(host.to_string())))
}
