pub mod dnsmasq;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;

use hickory_proto::rr::Name;
use tracing::{error, instrument, warn};

use crate::backend::{Backend, DynBackend};

#[derive(Default)]
pub struct Route {
    nodes: BTreeMap<String, Node>,
}

impl Debug for Route {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route").finish_non_exhaustive()
    }
}

struct Node {
    name: String,
    backend: Option<DynBackend>,
    children: BTreeMap<String, Node>,
}

impl Debug for Node {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.name)
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}

impl Node {
    fn new_empty(name: String) -> Self {
        Self {
            name,
            backend: None,
            children: Default::default(),
        }
    }
}

impl Route {
    pub fn import<R: Read>(&mut self, reader: R, backend: DynBackend) -> anyhow::Result<()> {
        let lines = BufReader::new(reader).lines();

        for line in lines {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('#') {
                continue;
            }

            self.insert(line.to_string(), Arc::clone(&backend));
        }

        Ok(())
    }

    pub fn insert(&mut self, domain: String, backend: DynBackend) {
        let names = domain.split('.').rev().filter(|s| !s.is_empty());
        let children = &mut self.nodes;

        assert!(Self::insert_inner(names, children, backend).is_none());
    }

    fn insert_inner<'a, I: Iterator<Item = &'a str>>(
        mut names: I,
        children: &mut BTreeMap<String, Node>,
        backend: DynBackend,
    ) -> Option<DynBackend> {
        match names.next() {
            None => Some(backend),

            Some(name) => match children.get_mut(name) {
                None => {
                    let child = children
                        .entry(name.to_string())
                        .or_insert_with(|| Node::new_empty(name.to_string()));

                    match Self::insert_inner(names, &mut child.children, backend) {
                        None => None,
                        Some(backend) => {
                            child.backend = Some(backend);

                            None
                        }
                    }
                }

                Some(child) => {
                    let children = &mut child.children;

                    if let Some(backend) = Self::insert_inner(names, children, backend) {
                        child.backend = Some(backend);
                    }

                    None
                }
            },
        }
    }

    #[instrument(skip(self), ret)]
    pub fn get_backend(&self, name: &Name) -> Option<&(dyn Backend + Send + Sync)> {
        let mut names = name.iter().rev().filter(|s| !s.is_empty());
        let root = match names.next() {
            None => {
                warn!("split domain first name should always exist");

                return None;
            }

            Some(root) => match str::from_utf8(root) {
                Err(err) => {
                    error!(%err, "invalid domain root");

                    return None;
                }

                Ok(root) => root,
            },
        };

        let mut node = self.nodes.get(root)?;

        for name in names {
            let name = match str::from_utf8(name) {
                Err(err) => {
                    error!(%err, "invalid domain name");

                    return None;
                }

                Ok(name) => name,
            };

            match node.children.get(name) {
                Some(child) => {
                    node = child;
                }

                None => return node.backend.as_deref(),
            }
        }

        node.backend.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use hickory_proto::op::Message;
    use hickory_proto::xfer::DnsResponse;

    use super::*;

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct TestBackend(pub usize);

    #[async_trait]
    impl Backend for TestBackend {
        async fn send_request(&self, _: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
            panic!("just for test")
        }
    }

    #[test]
    fn insert() {
        let mut route = Route::default();

        route.insert("www.example.com".to_string(), Arc::new(TestBackend(1)));
    }

    #[test]
    fn get() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), Arc::new(TestBackend(1)));

        assert!(route.get_backend(&"example.com".parse().unwrap()).is_some());
        assert!(
            route
                .get_backend(&"www.example.com".parse().unwrap())
                .is_some()
        );
        assert!(
            route
                .get_backend(&"www.test.example.com".parse().unwrap())
                .is_some()
        );
    }

    #[test]
    fn get_not_found() {
        let mut route = Route::default();

        route.insert("example.io".to_string(), Arc::new(TestBackend(1)));

        assert!(route.get_backend(&"example.com".parse().unwrap()).is_none());
        assert!(route.get_backend(&"io".parse().unwrap()).is_none());
    }

    #[test]
    fn multi() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), Arc::new(TestBackend(1)));
        route.insert("github.com".to_string(), Arc::new(TestBackend(2)));

        assert!(route.get_backend(&"example.com".parse().unwrap()).is_some());
        assert!(
            route
                .get_backend(&"www.example.com".parse().unwrap())
                .is_some()
        );
        assert!(
            route
                .get_backend(&"www.test.example.com".parse().unwrap())
                .is_some()
        );
        assert!(route.get_backend(&"github.com".parse().unwrap()).is_some());
        assert!(
            route
                .get_backend(&"www.github.com".parse().unwrap())
                .is_some()
        );
        assert!(
            route
                .get_backend(&"www.test.github.com".parse().unwrap())
                .is_some()
        );
    }
}
