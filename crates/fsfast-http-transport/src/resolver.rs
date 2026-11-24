//! A DNS resolver that spreads new connections over all of a host's
//! addresses.
//!
//! Object-store endpoints (S3, GCS) resolve to many IPs. The system resolver
//! returns them in a fixed order for a while, so every new connection goes to
//! the first address and the pool ends up concentrated on one server. AWS CRT
//! gets much of its S3 throughput from spreading connections over all
//! addresses; [`RotatingResolver`] does the same by rotating the address list
//! by one position on every lookup.
//!
//! The family order of the system answer is kept (IPv6 first if the system
//! prefers it), and addresses rotate within each family, so happy-eyeballs
//! behaviour in the connector is unchanged.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// Resolves through the system resolver (`getaddrinfo` on a blocking thread)
/// and rotates the answer per lookup. Enable with
/// [`HttpConfig::rotate_dns`](crate::HttpConfig::rotate_dns).
#[derive(Debug, Default)]
pub struct RotatingResolver {
    lookups: AtomicUsize,
}

impl RotatingResolver {
    /// A fresh resolver.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Resolve for RotatingResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let turn = self.lookups.fetch_add(1, Ordering::Relaxed);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // `lookup_host` runs getaddrinfo via spawn_blocking: the runtime
            // is never blocked. Port 0: the connector sets the real port.
            let addrs: Vec<SocketAddr> =
                tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            let addrs = rotate(dedup(addrs), turn);
            tracing::trace!(%host, ?addrs, "resolved");
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Drop repeated addresses, keeping the first occurrence.
fn dedup(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(addrs.len());
    for a in addrs {
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Rotate the addresses of each family left by `turn`, keeping the families
/// in the order in which they first appear.
pub(crate) fn rotate(addrs: Vec<SocketAddr>, turn: usize) -> Vec<SocketAddr> {
    let Some(first) = addrs.first() else {
        return addrs;
    };
    let first_is_v6 = first.is_ipv6();
    let (mut a, mut b): (Vec<_>, Vec<_>) =
        addrs.into_iter().partition(|x| x.is_ipv6() == first_is_v6);
    if !a.is_empty() {
        let n = turn % a.len();
        a.rotate_left(n);
    }
    if !b.is_empty() {
        let n = turn % b.len();
        b.rotate_left(n);
    }
    a.extend(b);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], 0))
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::from(([0xfd00, 0, 0, 0, 0, 0, 0, last], 0))
    }

    #[test]
    fn rotates_within_families_keeping_family_order() {
        let addrs = vec![v6(1), v4(1), v6(2), v4(2), v4(3)];
        assert_eq!(
            rotate(addrs.clone(), 0),
            vec![v6(1), v6(2), v4(1), v4(2), v4(3)]
        );
        assert_eq!(
            rotate(addrs.clone(), 1),
            vec![v6(2), v6(1), v4(2), v4(3), v4(1)]
        );
        assert_eq!(
            rotate(addrs.clone(), 2),
            vec![v6(1), v6(2), v4(3), v4(1), v4(2)]
        );
        assert!(rotate(Vec::new(), 3).is_empty());
    }

    #[test]
    fn every_address_comes_first_in_turn() {
        let addrs: Vec<_> = (1..=4).map(v4).collect();
        let firsts: Vec<_> = (0..4).map(|t| rotate(addrs.clone(), t)[0]).collect();
        assert_eq!(firsts, addrs);
    }

    #[test]
    fn dedup_keeps_first_occurrence() {
        assert_eq!(dedup(vec![v4(1), v4(2), v4(1)]), vec![v4(1), v4(2)]);
    }

    #[tokio::test]
    async fn resolves_localhost_and_rotates() {
        let r = RotatingResolver::new();
        let first: Vec<_> = r
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .collect();
        assert!(!first.is_empty());
        assert!(first.iter().all(|a| a.ip().is_loopback()));
        let second: Vec<_> = r
            .resolve("localhost".parse().unwrap())
            .await
            .unwrap()
            .collect();
        let mut a = first.clone();
        let mut b = second.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b, "same set of addresses on every lookup");
    }
}
