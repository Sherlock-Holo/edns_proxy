use std::io;
use std::num::NonZeroUsize;
use std::time::Duration;

use compio::{BufResult, time};

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

pub trait TimeoutExt: Future {
    async fn timeout(self, dur: Duration) -> io::Result<Self::Output>;
}

impl<F: Future> TimeoutExt for F {
    #[inline]
    async fn timeout(self, dur: Duration) -> io::Result<Self::Output> {
        time::timeout(dur, self)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::TimedOut, err))
    }
}

pub trait PartsExt {
    type Output;

    fn to_parts(self) -> Self::Output;
}

impl<T, B> PartsExt for BufResult<T, B> {
    type Output = (io::Result<T>, B);

    #[inline]
    fn to_parts(self) -> Self::Output {
        let BufResult(res, buf) = self;

        (res, buf)
    }
}
