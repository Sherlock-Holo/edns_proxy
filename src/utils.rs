use std::num::NonZeroUsize;

/// Retries the async operation up to `attempts` times.
/// Uses `FnMut() -> Fut` with explicit `Fut: Send` bound so the future type is
/// not over-constrained by `AsyncFnMut` (which can trigger "Send not general enough").
#[inline]
pub async fn retry<T, E, F, Fut>(attempts: NonZeroUsize, mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    for i in 0..attempts.get() {
        match f().await {
            Ok(res) => return Ok(res),
            Err(err) => {
                if i + 1 >= attempts.get() {
                    return Err(err);
                }
            }
        }
    }

    unreachable!("")
}
