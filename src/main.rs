use anyhow::Result;
use clap::{Parser, Subcommand};

mod auth;
mod config;
mod crypto;
mod database;
mod messages;
mod server;
mod ui;

#[derive(Parser)]
#[command(name = "dood")]
#[command(about = "DooD - End-to-End Encrypted Messenger CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set the server URL (required before registration)
    SetServer {
        /// Server URL to use
        #[arg(short, long)]
        url: String,
    },

    /// Register a new account
    Register {
        /// Username to register
        #[arg(short, long)]
        username: String,
    },

    /// Login to existing account
    Login {
        /// Username to login
        #[arg(short, long)]
        username: String,
    },

    /// Send a message to a user
    Send {
        /// Recipient username
        #[arg(short, long)]
        to: String,

        /// Message text
        #[arg(short, long)]
        message: String,
    },

    /// Fetch and display new messages
    Fetch,

    /// List all conversations
    Chats,

    /// View conversation history with a user
    History {
        /// Username to view history with
        username: String,

        /// Number of messages to show (default: 50)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Start interactive chat mode
    Chat {
        /// Username to chat with
        username: String,
    },

    /// Export account keys (backup)
    Export {
        /// Output file path
        #[arg(short, long)]
        output: String,
    },

    /// Import account keys (restore)
    Import {
        /// Input file path
        #[arg(short, long)]
        input: String,
    },

    /// Show account information
    Info,

    /// Logout and clear session
    Logout,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    database::init()?;

    match cli.command {
        Commands::SetServer { url } => {
            config::set_server_url(&url)?;
        }

        Commands::Register { username } => {
            ensure_server_configured()?;
            auth::register(&username).await?;
        }

        Commands::Login { username } => {
            auth::login(&username)?;
        }

        Commands::Send { to, message } => {
            ensure_logged_in()?;
            messages::send_message(&to, &message).await?;
        }

        Commands::Fetch => {
            ensure_logged_in()?;
            messages::fetch_messages().await?;
        }

        Commands::Chats => {
            ensure_logged_in()?;
            ui::display_chats()?;
        }

        Commands::History { username, limit } => {
            ensure_logged_in()?;
            ui::display_history(&username, limit)?;
        }

        Commands::Chat { username } => {
            ensure_logged_in()?;
            ui::interactive_chat(&username).await?;
        }

        Commands::Export { output } => {
            ensure_logged_in()?;
            crypto::export_keys(&output)?;
        }

        Commands::Import { input } => {
            crypto::import_keys(&input)?;
        }

        Commands::Info => {
            ensure_logged_in()?;
            ui::display_account_info()?;
        }

        Commands::Logout => {
            auth::logout()?;
        }
    }

    Ok(())
}

fn ensure_logged_in() -> Result<()> {
    if !auth::is_logged_in()? {
        anyhow::bail!("Not logged in. Please run 'dood login' first.");
    }
    Ok(())
}

fn ensure_server_configured() -> Result<()> {
    if !config::is_server_configured()? {
        anyhow::bail!(
            "Server URL not configured. Please run 'dood set-server --url <SERVER_URL>' first."
        );
    }
    Ok(())
}
