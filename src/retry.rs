use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::time::Duration;

use tokio::time::sleep;

pub async fn retry<F, H, T, E>(
    mut func: F,
    mut err_handle: H,
    count: NonZeroUsize,
    sleep_interval: Option<Duration>,
) -> Result<T, E>
where
    F: AsyncFnMut() -> Result<T, E>,
    H: AsyncFnMut(E) -> ControlFlow<E, E>,
{
    let mut err = MaybeUninit::uninit();
    for _ in 0..count.get() {
        match func().await {
            Err(e) => {
                match err_handle(e).await {
                    ControlFlow::Break(e) => return Err(e),
                    ControlFlow::Continue(e) => {
                        err.write(e);
                    }
                }

                if let Some(interval) = sleep_interval {
                    sleep(interval).await;
                }
            }

            Ok(v) => return Ok(v),
        }
    }

    unsafe { Err(err.assume_init()) }
}
