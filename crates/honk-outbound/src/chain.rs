//! Outbound chaining ("detour"): a node reaches its own server through a
//! front node instead of a direct TCP connect.
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

/// Connect to `node`'s own server endpoint through its front hop.
///
/// Only valid for a node with a detour; direct dials keep their concrete
/// `ObservedTcp` path. The returned stream is owned by the caller.
pub async fn connect_server(
    node: &Node,
    connect_timeout: Duration,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
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
    Ok(proxy.stream)
}

/// Resolve the front node's stable id inside `generation`. A duplicated
/// display name is refused rather than silently picking the first: the
/// operator validator rejects ambiguity, but subscription-imported names are
/// not covered there.
fn resolve_front(
    generation: &Arc<OutboundRuntimeRegistry>,
    front_name: &str,
) -> anyhow::Result<uuid::Uuid> {
    let mut matches = generation
        .values()
        .filter(|runtime| runtime.node.name == front_name);
    let Some(front) = matches.next() else {
        anyhow::bail!("detour target '{front_name}' is not in the current runtime generation");
    };
    if matches.next().is_some() {
        anyhow::bail!("detour target '{front_name}' is ambiguous (duplicate node name)");
    }
    match front.node.protocol() {
        honk_config::types::NodeProtocol::Direct | honk_config::types::NodeProtocol::Block => {
            anyhow::bail!("detour target '{front_name}' is a built-in node")
        }
        _ => Ok(front.node.id),
    }
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
