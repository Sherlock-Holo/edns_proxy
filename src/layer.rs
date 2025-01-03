use std::sync::Arc;

use tower::Layer;
use tower::layer::layer_fn;
use tower::layer::util::Identity;

use crate::backend::Backend;

pub struct LayerBuilder {
    layer: Box<dyn Layer<Arc<dyn Backend + Send + Sync>, Service = Arc<dyn Backend + Send + Sync>>>,
}

impl LayerBuilder {
    pub fn new() -> Self {
        Self {
            layer: Box::new(Identity::new()),
        }
    }

    pub fn layer<L>(self, layer: L) -> LayerBuilder
    where
        L: Layer<Arc<dyn Backend + Send + Sync>, Service = Arc<dyn Backend + Send + Sync>>
            + 'static,
    {
        LayerBuilder {
            layer: Box::new(layer_fn(move |backend| {
                let backend = self.layer.layer(Arc::new(backend));

                layer.layer(backend)
            })),
        }
    }

    pub fn build<B: Backend + Send + Sync + 'static>(
        self,
        backend: B,
    ) -> Arc<dyn Backend + Send + Sync> {
        let service = self.layer.layer(Arc::new(backend));

        Arc::new(service)
    }
}
