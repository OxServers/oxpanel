//! Peer authentication for the UNIX socket.
//!
//! There is no in-band authentication: the kernel tells us who connected
//! (`SO_PEERCRED`) and we compare that against an allow-list *before* the
//! connection ever reaches the HTTP/2 stack. Unauthorised peers are closed
//! immediately; authorised ones are wrapped in [`AuthedStream`], whose
//! connect-info carries the verified [`PeerInfo`] into every request.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::server::Connected;
use tracing::{debug, warn};

use crate::config::Config;
use crate::system::System;

/// Kernel-verified identity of a connected peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

impl std::fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "uid={} gid={} pid={pid}", self.uid, self.gid),
            None => write!(f, "uid={} gid={}", self.uid, self.gid),
        }
    }
}

/// Who may talk to the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPolicy {
    allowed_uids: BTreeSet<u32>,
    allowed_gids: BTreeSet<u32>,
    allow_root: bool,
}

impl PeerPolicy {
    pub fn new(allowed_uids: BTreeSet<u32>, allowed_gids: BTreeSet<u32>, allow_root: bool) -> Self {
        Self {
            allowed_uids,
            allowed_gids,
            allow_root,
        }
    }

    /// Policy from configuration; the socket group (if resolved) is allowed.
    pub fn from_config(config: &Config, socket_gid: Option<u32>) -> Self {
        let mut gids = config.allowed_gids.clone();
        gids.extend(socket_gid);
        Self::new(config.allowed_uids.clone(), gids, config.allow_root_peer)
    }

    /// `groups` are the peer's supplementary groups, if resolved.
    pub fn is_allowed(&self, peer: &PeerInfo, groups: &[u32]) -> bool {
        (self.allow_root && peer.uid == 0)
            || self.allowed_uids.contains(&peer.uid)
            || self.allowed_gids.contains(&peer.gid)
            || groups.iter().any(|g| self.allowed_gids.contains(g))
    }

    pub fn has_gid_rules(&self) -> bool {
        !self.allowed_gids.is_empty()
    }

    /// True when only root (at most) can connect — worth a startup warning.
    pub fn only_root(&self) -> bool {
        self.allowed_uids.is_empty() && self.allowed_gids.is_empty()
    }
}

/// A class of RPCs a peer may be limited to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Get/List RPCs, usage, host information, reconciliation.
    Read,
    /// `ConfigureVirtualHost`, `RemoveVirtualHost`.
    VHost,
    /// `CreateTenant`, the update RPCs, suspend and resume.
    Tenant,
    /// `DeleteTenant`.
    Delete,
}

impl Scope {
    pub const ALL: [Self; 4] = [Self::Read, Self::VHost, Self::Tenant, Self::Delete];

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "read" => Some(Self::Read),
            "vhost" => Some(Self::VHost),
            "tenant" => Some(Self::Tenant),
            "delete" => Some(Self::Delete),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::VHost => "vhost",
            Self::Tenant => "tenant",
            Self::Delete => "delete",
        }
    }
}

/// Per-peer limits on *what* an already authenticated peer may call.
///
/// A uid with an entry may call only RPCs in its scopes; a uid without one
/// is unrestricted. This lets a customer-facing service account be confined
/// to, say, `read+vhost`, so that compromising it can never reach
/// `DeleteTenant`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopePolicy {
    by_uid: BTreeMap<u32, BTreeSet<Scope>>,
}

impl ScopePolicy {
    pub fn new(by_uid: BTreeMap<u32, BTreeSet<Scope>>) -> Self {
        Self { by_uid }
    }

    pub fn permits(&self, peer: &PeerInfo, scope: Scope) -> bool {
        self.by_uid
            .get(&peer.uid)
            .is_none_or(|allowed| allowed.contains(&scope))
    }
}

/// A `UnixStream` that has passed [`PeerPolicy`].
#[derive(Debug)]
pub struct AuthedStream {
    inner: UnixStream,
    peer: PeerInfo,
}

impl Connected for AuthedStream {
    type ConnectInfo = PeerInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.peer.clone()
    }
}

impl AsyncRead for AuthedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Accept connections, authenticate each one, and yield only the authorised.
///
/// The accept loop runs in its own task so a slow group lookup for one peer
/// never blocks the server, and so unauthenticated peers never touch the
/// protocol stack at all.
pub fn gate(
    listener: UnixListener,
    policy: Arc<PeerPolicy>,
    sys: Arc<dyn System>,
) -> ReceiverStream<io::Result<AuthedStream>> {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => match authenticate(&stream, &policy, sys.as_ref()).await {
                    Ok(peer) => {
                        debug!(%peer, "peer authorised");
                        if tx
                            .send(Ok(AuthedStream {
                                inner: stream,
                                peer,
                            }))
                            .await
                            .is_err()
                        {
                            break; // server gone
                        }
                    }
                    Err(reason) => {
                        warn!(%reason, "rejected connection");
                        drop(stream);
                    }
                },
                Err(e) => {
                    // EMFILE/ENFILE/ECONNABORTED are transient; back off instead of spinning.
                    warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });
    ReceiverStream::new(rx)
}

async fn authenticate(
    stream: &UnixStream,
    policy: &PeerPolicy,
    sys: &dyn System,
) -> Result<PeerInfo, String> {
    let cred = stream
        .peer_cred()
        .map_err(|e| format!("SO_PEERCRED unavailable: {e}"))?;
    let peer = PeerInfo {
        uid: cred.uid(),
        gid: cred.gid(),
        pid: cred.pid(),
    };
    if policy.is_allowed(&peer, &[]) {
        return Ok(peer);
    }
    if policy.has_gid_rules() {
        // Supplementary groups are not in SO_PEERCRED; resolve them.
        if let Ok(Some(user)) = sys.user_by_uid(peer.uid).await {
            if let Ok(groups) = sys.groups_of(&user.name, user.gid).await {
                if policy.is_allowed(&peer, &groups) {
                    return Ok(peer);
                }
            }
        }
    }
    Err(format!("{peer} is not in the allow-list"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(v: &[u32]) -> BTreeSet<u32> {
        v.iter().copied().collect()
    }

    #[test]
    fn policy_decisions() {
        let p = PeerPolicy::new(set(&[1001]), set(&[990]), true);
        let root = PeerInfo {
            uid: 0,
            gid: 0,
            pid: None,
        };
        let api = PeerInfo {
            uid: 1001,
            gid: 1001,
            pid: Some(4),
        };
        let member = PeerInfo {
            uid: 1002,
            gid: 990,
            pid: None,
        };
        let supp = PeerInfo {
            uid: 1003,
            gid: 1003,
            pid: None,
        };
        let stranger = PeerInfo {
            uid: 2000,
            gid: 2000,
            pid: None,
        };
        assert!(p.is_allowed(&root, &[]));
        assert!(p.is_allowed(&api, &[]));
        assert!(p.is_allowed(&member, &[]));
        assert!(!p.is_allowed(&supp, &[]));
        assert!(p.is_allowed(&supp, &[1003, 990]));
        assert!(!p.is_allowed(&stranger, &[2000, 100]));
        let no_root = PeerPolicy::new(set(&[]), set(&[]), false);
        assert!(!no_root.is_allowed(&root, &[]));
        assert!(no_root.only_root());
        assert!(!p.only_root());
    }

    /// A peer whose *account* is in an allowed group is let in although
    /// SO_PEERCRED cannot say so: the supplementary groups come from the
    /// account database (covered end to end by the integration suite, here
    /// with the fake one).
    #[tokio::test]
    async fn supplementary_groups_come_from_the_account_database() {
        use crate::system::{FakeSystem, OsUser};
        let (a, _b) = UnixStream::pair().unwrap_or_else(|e| panic!("socketpair: {e}"));
        let me = a.peer_cred().unwrap_or_else(|e| panic!("peer_cred: {e}"));
        let sys = FakeSystem::new();
        sys.add_user(OsUser {
            name: "panelapi".into(),
            uid: me.uid(),
            gid: me.gid(),
            home: "/".into(),
            shell: "/sbin/nologin".into(),
        });
        let policy = PeerPolicy::new(set(&[]), set(&[4242]), false);
        assert!(
            authenticate(&a, &policy, &sys).await.is_err(),
            "not in the allowed group yet"
        );
        sys.add_membership("panelapi", 4242);
        let peer = authenticate(&a, &policy, &sys)
            .await
            .unwrap_or_else(|e| panic!("should be allowed: {e}"));
        assert_eq!(peer.uid, me.uid());
        // An unknown account is refused, not an error.
        let stranger = PeerPolicy::new(set(&[]), set(&[4242]), false);
        assert!(authenticate(&a, &stranger, &FakeSystem::new())
            .await
            .is_err());
    }

    #[test]
    fn scopes_confine_listed_uids_only() {
        let peer = |uid| PeerInfo {
            uid,
            gid: uid,
            pid: None,
        };
        let policy = ScopePolicy::new(
            [(1001, [Scope::Read, Scope::VHost].into_iter().collect())]
                .into_iter()
                .collect(),
        );
        assert!(policy.permits(&peer(1001), Scope::Read));
        assert!(policy.permits(&peer(1001), Scope::VHost));
        assert!(!policy.permits(&peer(1001), Scope::Tenant));
        assert!(!policy.permits(&peer(1001), Scope::Delete));
        for s in Scope::ALL {
            assert!(
                policy.permits(&peer(1002), s),
                "unlisted uid is unrestricted"
            );
            assert!(ScopePolicy::default().permits(&peer(1001), s));
            assert_eq!(Scope::parse(s.as_str()), Some(s));
        }
        assert_eq!(Scope::parse("admin"), None);
    }

    #[test]
    fn from_config_includes_socket_group() {
        let mut c = Config::default();
        c.allowed_gids = set(&[5]);
        let p = PeerPolicy::from_config(&c, Some(77));
        assert!(p.is_allowed(
            &PeerInfo {
                uid: 9,
                gid: 77,
                pid: None
            },
            &[]
        ));
        assert!(p.is_allowed(
            &PeerInfo {
                uid: 9,
                gid: 5,
                pid: None
            },
            &[]
        ));
        assert!(!p.is_allowed(
            &PeerInfo {
                uid: 9,
                gid: 6,
                pid: None
            },
            &[]
        ));
    }
}
