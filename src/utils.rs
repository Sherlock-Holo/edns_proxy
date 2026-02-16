use std::time::Duration;

use tokio::time;
use tokio::time::Timeout;

pub trait TimeoutExt {
    fn timeout(self, timeout: Duration) -> Timeout<Self>
    where
        Self: Sized;
}

impl<F: Future> TimeoutExt for F {
    fn timeout(self, timeout: Duration) -> Timeout<Self> {
        time::timeout(timeout, self)
    }
}
