use time::OffsetDateTime;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
pub trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;
}

pub struct DefaultClock;

impl Clock for DefaultClock {
    fn now_utc(&self) -> OffsetDateTime {
        crate::clock::now_utc()
    }
}

#[cfg(test)]
tokio::task_local! {
    static MOCKED_NOW: OffsetDateTime;
}

/// Test clock reading the time set by [`run_with_mocked_time_async`], falling back to the real
/// time outside of it.
#[cfg(test)]
pub(crate) struct TaskLocalClock;

#[cfg(test)]
impl Clock for TaskLocalClock {
    fn now_utc(&self) -> OffsetDateTime {
        MOCKED_NOW
            .try_with(|now| *now)
            .unwrap_or_else(|_| crate::clock::now_utc())
    }
}

#[cfg(test)]
pub(crate) async fn run_with_mocked_time_async<F: std::future::Future>(
    now: OffsetDateTime,
    future: F,
) -> F::Output {
    MOCKED_NOW.scope(now, future).await
}
