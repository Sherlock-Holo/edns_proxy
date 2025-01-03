use std::sync::Arc;

use tower::Layer;

use crate::backend::Backend;

mod ecs;

pub struct BoxLayer {
    layer: Arc<dyn Layer<Box<dyn Backend + Send + Sync>, Service = Box<dyn Backend + Send + Sync>>>,
}

impl BoxLayer {
    pub fn new<L>(layer: L) -> Self
    where
        L: Layer<Box<dyn Backend + Send + Sync>, Service = Box<dyn Backend + Send + Sync>>
            + 'static,
    {
        Self {
            layer: Arc::new(layer),
        }
    }
}

impl<B: Backend + Send + Sync + 'static> Layer<B> for BoxLayer {
    type Service = Box<dyn Backend + Send + Sync>;

    fn layer(&self, inner: B) -> Self::Service {
        self.layer.layer(Box::new(inner))
    }
}
