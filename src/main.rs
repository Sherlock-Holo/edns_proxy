use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    edns_proxy::run().await
}
