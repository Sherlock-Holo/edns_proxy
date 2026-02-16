use tower::Layer;
use tower::layer::layer_fn;
use tower::layer::util::Identity;

use crate::backend::{Backend, DynBackend};

pub struct LayerBuilder {
    layer: Box<dyn Layer<DynBackend, Service = DynBackend>>,
}

impl LayerBuilder {
    pub fn new() -> Self {
        Self {
            layer: Box::new(Identity::new()),
        }
    }

    pub fn layer<L>(self, layer: L) -> LayerBuilder
    where
        L: Layer<DynBackend, Service = DynBackend> + 'static,
    {
        LayerBuilder {
            layer: Box::new(layer_fn(move |backend| {
                let backend = self.layer.layer(backend);

                layer.layer(backend)
            })),
        }
    }

    pub fn build<B: Backend + Send + Sync + 'static>(self, backend: B) -> DynBackend {
        let service = self.layer.layer(Box::new(backend));

        Box::new(service)
    }
}
