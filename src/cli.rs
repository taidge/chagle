use clap::{ArgGroup, Parser, ValueEnum};
use std::sync::LazyLock;

#[derive(ValueEnum, Clone, Debug, Copy)]
pub enum KeypairType {
    X25519,
    X448,
}

static VERSION: LazyLock<&str> = LazyLock::new(|| {
    option_env!("VERGEN_GIT_DESCRIBE").unwrap_or(env!("CARGO_PKG_VERSION"))
});

static LONG_VERSION: LazyLock<String> = LazyLock::new(|| {
    format!(
        "
Build Timestamp:     {}
Build Version:       {}
Commit SHA:          {}
Commit Branch:       {}
cargo Target Triple: {}
",
        option_env!("VERGEN_BUILD_TIMESTAMP").unwrap_or("unknown"),
        env!("CARGO_PKG_VERSION"),
        option_env!("VERGEN_GIT_SHA").unwrap_or("unknown"),
        option_env!("VERGEN_GIT_BRANCH").unwrap_or("unknown"),
        option_env!("VERGEN_CARGO_TARGET_TRIPLE").unwrap_or("unknown"),
    )
});

#[derive(Parser, Debug, Default, Clone)]
#[command(
    about,
    version(&**VERSION),
    long_version(LONG_VERSION.as_str()),
    next_display_order = None,
)]
#[command(group(
    ArgGroup::new("cmds")
        .required(true)
        .args(&["CONFIG", "genkey"]),
))]
pub struct Cli {
    /// The path to the configuration file
    ///
    /// Running as a client or a server is automatically determined
    /// according to the configuration file.
    #[arg(name = "CONFIG")]
    pub config_path: Option<std::path::PathBuf>,

    /// Run as a server
    #[arg(long, short, group = "mode")]
    pub server: bool,

    /// Run as a client
    #[arg(long, short, group = "mode")]
    pub client: bool,

    /// Generate a keypair for the use of the noise protocol
    ///
    /// The DH function to use is x25519
    #[arg(long, value_enum, value_name = "CURVE")]
    pub genkey: Option<Option<KeypairType>>,

    /// Verify the configuration file and exit
    #[arg(long)]
    pub verify: bool,
}
