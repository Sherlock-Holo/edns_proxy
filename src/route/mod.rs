pub mod dnsmasq;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::io::{BufRead, BufReader, Read};

use tracing::{instrument, warn};

use crate::backend::Backend;

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
    backend: Option<Box<dyn Backend + Send + Sync>>,
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
    pub fn import<R: Read, B: Backend + Send + Sync + Clone + 'static>(
        &mut self,
        reader: R,
        backend: B,
    ) -> anyhow::Result<()> {
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

            self.insert(line.to_string(), backend.clone());
        }

        Ok(())
    }

    pub fn insert<B: Backend + Send + Sync + 'static>(&mut self, domain: String, backend: B) {
        let names = domain.split('.').rev().filter(|s| !s.is_empty());
        let children = &mut self.nodes;

        assert!(Self::insert_inner(names, children, backend).is_none());
    }

    fn insert_inner<'a, I: Iterator<Item = &'a str>, B: Backend + Send + Sync + 'static>(
        mut names: I,
        children: &mut BTreeMap<String, Node>,
        backend: B,
    ) -> Option<B> {
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
                            child.backend = Some(Box::new(backend));

                            None
                        }
                    }
                }

                Some(child) => {
                    let children = &mut child.children;

                    if let Some(backend) = Self::insert_inner(names, children, backend) {
                        child.backend = Some(Box::new(backend));
                    }

                    None
                }
            },
        }
    }

    #[instrument(ret)]
    pub fn get_backend(&self, domain: &str) -> Option<&(dyn Backend + Send + Sync)> {
        let mut names = domain.split('.').rev().filter(|s| !s.is_empty());
        let root = match names.next() {
            None => {
                warn!(domain, "split domain first name should always exist");

                return None;
            }

            Some(root) => root,
        };
        let mut node = self.nodes.get(root)?;

        for name in names {
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

    use async_trait::async_trait;
    use hickory_proto::op::Message;
    use hickory_proto::xfer::DnsResponse;

    use super::*;
    use crate::backend::DynBackend;

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub struct TestBackend(pub usize);

    #[async_trait]
    impl Backend for TestBackend {
        async fn send_request(&self, _: Message, _: SocketAddr) -> anyhow::Result<DnsResponse> {
            panic!("just for test")
        }

        fn to_dyn_clone(&self) -> DynBackend {
            Box::new(*self)
        }
    }

    #[test]
    fn insert() {
        let mut route = Route::default();

        route.insert("www.example.com".to_string(), TestBackend(1));
    }

    #[test]
    fn get() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), TestBackend(1));

        assert!(route.get_backend("example.com").is_some());
        assert!(route.get_backend("www.example.com").is_some());
        assert!(route.get_backend("www.test.example.com").is_some());
    }

    #[test]
    fn get_not_found() {
        let mut route = Route::default();

        route.insert("example.io".to_string(), TestBackend(1));

        assert!(route.get_backend("example.com").is_none());
        assert!(route.get_backend("io").is_none());
    }

    #[test]
    fn multi() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), TestBackend(1));
        route.insert("github.com".to_string(), TestBackend(2));

        assert!(route.get_backend("example.com").is_some());
        assert!(route.get_backend("www.example.com").is_some());
        assert!(route.get_backend("www.test.example.com").is_some());
        assert!(route.get_backend("github.com").is_some());
        assert!(route.get_backend("www.github.com").is_some());
        assert!(route.get_backend("www.test.github.com").is_some());
    }
}
