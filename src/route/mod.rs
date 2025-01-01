pub mod dnsmasq;

use std::collections::BTreeMap;
use std::fmt::{Debug, Formatter};
use std::io::{BufRead, BufReader, Read};

use tracing::{instrument, warn};

use crate::backend::Backends;

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
    backend: Option<Backends>,
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
    pub fn import<R: Read>(&mut self, reader: R, backend: Backends) -> anyhow::Result<()> {
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

    pub fn insert(&mut self, domain: String, backend: Backends) {
        let names = domain.split('.').rev().filter(|s| !s.is_empty());
        let children = &mut self.nodes;

        assert!(Self::insert_inner(names, children, backend).is_none());
    }

    fn insert_inner<'a, I: Iterator<Item = &'a str>>(
        mut names: I,
        children: &mut BTreeMap<String, Node>,
        backend: Backends,
    ) -> Option<Backends> {
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

    #[instrument(ret)]
    pub fn get_backend(&self, domain: &str) -> Option<&Backends> {
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

                None => return node.backend.as_ref(),
            }
        }

        node.backend.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::TestBackend;

    #[test]
    fn insert() {
        let mut route = Route::default();

        route.insert("www.example.com".to_string(), TestBackend(1).into());
    }

    #[test]
    fn get() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), TestBackend(1).into());

        assert!(matches!(
            route.get_backend("example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));

        assert!(matches!(
            route.get_backend("www.example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));

        assert!(matches!(
            route.get_backend("www.test.example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));
    }

    #[test]
    fn get_not_found() {
        let mut route = Route::default();

        route.insert("example.io".to_string(), TestBackend(1).into());

        assert!(route.get_backend("example.com").is_none());
        assert!(route.get_backend("io").is_none());
    }

    #[test]
    fn multi() {
        let mut route = Route::default();

        route.insert("example.com".to_string(), TestBackend(1).into());
        route.insert("github.com".to_string(), TestBackend(2).into());

        assert!(matches!(
            route.get_backend("example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));

        assert!(matches!(
            route.get_backend("www.example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));

        assert!(matches!(
            route.get_backend("www.test.example.com").unwrap(),
            Backends::Test(TestBackend(1))
        ));

        assert!(matches!(
            route.get_backend("github.com").unwrap(),
            Backends::Test(TestBackend(2))
        ));

        assert!(matches!(
            route.get_backend("www.github.com").unwrap(),
            Backends::Test(TestBackend(2))
        ));

        assert!(matches!(
            route.get_backend("www.test.github.com").unwrap(),
            Backends::Test(TestBackend(2))
        ));
    }
}
