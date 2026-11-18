use std::{path::PathBuf, sync::Arc};

use agentdesktop_controller::{
    application,
    database::Database,
    management::{self, Extensions},
    management::auth::Provider,
    management::auth::providers::mcf::{Config as McfAuthConfig, McfAccess},
};
use agentdesktop_core::{DEFAULT_CONTROLLER_CONFIG_PATH, config, telemetry};
use clap::Parser;

#[derive(Parser)]
#[command(about = "Agentdesktop fleet controller")]
struct Args {
    /// Path to the controller YAML configuration file.
    #[arg(long, default_value = DEFAULT_CONTROLLER_CONFIG_PATH)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let _log_flush = telemetry::setup_logging("info", false, None)?;
    let config = config::load_controller(&args.config)?;
    let database = Database::connect(&config.database_url).await?
    let authentication: Option<Arc<dyn Provider>> = match &config.admin_access {
        config::ControllerAdminAccess::Local => None,
        config::ControllerAdminAccess::Authenticated(admin) => {
            let provider_type = admin.provider.get("type").and_then(|value| value.as_str()).unwrap_or("mcf");
            anyhow::ensure!(provider_type == "mcf", "unsupported controller admin provider: {provider_type}");
            let provider = serde_json::from_value::<McfAuthConfig>(serde_json::Value::Object(admin.provider.clone()))
                .map_err(|error| anyhow::anyhow!("invalid MCF admin provider configuration: {error}"))?;
            Some(Arc::new(McfAccess::new(provider, admin.public_url.clone()).await?) as Arc<dyn Provider>)
        }
    };
    let extensions = Extensions { authentication, ..Extensions::default() };
    application::run(config, database, extensions).await
}
