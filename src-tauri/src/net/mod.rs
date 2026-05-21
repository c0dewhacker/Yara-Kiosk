pub mod gti;
pub mod yara_forge;

pub fn build_client() -> Result<reqwest::Client, anyhow::Error> {
    Ok(reqwest::Client::builder().use_rustls_tls().build()?)
}
