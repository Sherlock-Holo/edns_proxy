#[tokio::main]
async fn main() -> anyhow::Result<()> {
    edns_proxy::run().await
}
