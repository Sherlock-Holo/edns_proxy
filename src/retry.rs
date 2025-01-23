use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::time::Duration;

use tokio::time::sleep;

pub async fn retry<F, H, T, E, Cx>(
    mut cx: Cx,
    mut func: F,
    mut err_handle: H,
    count: NonZeroUsize,
    sleep_interval: Option<Duration>,
) -> Result<T, E>
where
    F: AsyncFnMut(&mut Cx) -> Result<T, E>,
    H: AsyncFnMut(E, &mut Cx) -> ControlFlow<E, E>,
{
    let mut err = None;
    for _ in 0..count.get() {
        match func(&mut cx).await {
            Err(e) => {
                match err_handle(e, &mut cx).await {
                    ControlFlow::Break(e) => return Err(e),
                    ControlFlow::Continue(e) => {
                        err = Some(e);
                    }
                }

                if let Some(interval) = sleep_interval {
                    sleep(interval).await;
                }
            }

            Ok(v) => return Ok(v),
        }
    }

    Err(err.unwrap())
}
