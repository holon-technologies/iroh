use super::*;

/// Future returned from [`Endpoint::closed`].
#[derive(derive_more::Debug)]
#[pin_project]
#[debug("EndpointClosed")]
pub struct EndpointClosed {
    #[pin]
    pub(super) inner: WaitForCancellationFutureOwned,
}

impl Future for EndpointClosed {
    type Output = ();

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.project();
        this.inner.poll(cx)
    }
}

impl EndpointClosed {
    /// Runs a future to completion, or until the [`Endpoint`] is closed.
    ///
    /// Returns the output of `fut` if it completes before the endpoint closes,
    /// or `None` otherwise.
    pub async fn run_until<F: Future>(self, fut: F) -> Option<F::Output> {
        n0_future::future::or(async { Some(fut.await) }, async {
            self.await;
            None
        })
        .await
    }
}
