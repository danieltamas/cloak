use clap::{Parser, Subcommand};
use colored::Colorize;

mod auth;
mod commands;
mod detector;
mod envparser;
mod filemanager;
mod keychain;
#[allow(dead_code)]
mod license;
mod platform;
mod recovery;
mod sandbox;
mod vault;
mod version;

const BANNER: &str = r#"
   ██████╗██╗      ██████╗  █████╗ ██╗  ██╗
  ██╔════╝██║     ██╔═══██╗██╔══██╗██║ ██╔╝
  ██║     ██║     ██║   ██║███████║█████╔╝
  ██║     ██║     ██║   ██║██╔══██║██╔═██╗
  ╚██████╗███████╗╚██████╔╝██║  ██║██║  ██╗
   ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"#;

const SUPPORT_MESSAGES: &[(&str, &str)] = &[
    ("BUY ME a mass spectrometer from 1987", "42.00"),
    ("BUY ME a mass-produced samurai sword from alibaba", "9.99"),
    ("BUY ME a used roomba with trust issues", "9.99"),
    (
        "BUY ME a 55-gallon drum of lube (it's for the servers)",
        "69.00",
    ),
    ("BUY ME a nokia 3310 (for emotional support)", "9.99"),
    (
        "BUY ME a life-size cardboard cutout of linus torvalds",
        "13.37",
    ),
    ("BUY ME an industrial cheese wheel", "19.99"),
    ("BUY ME a decommissioned stop sign", "11.00"),
    ("BUY ME a bluetooth-enabled ouija board", "19.19"),
    ("BUY ME a used oscilloscope with existential dread", "11.11"),
    ("BUY ME a vintage 56k modem for nostalgia reasons", "14.40"),
    ("BUY ME a 3d-printed tyrannosaurus femur", "18.88"),
    ("BUY ME a taxidermied squirrel in business casual", "14.99"),
    ("BUY ME a fog machine for the standup meeting", "24.99"),
    (
        "BUY ME a rotary phone that makes me feel important",
        "31.41",
    ),
    ("BUY ME a nasa surplus o-ring (unused, obviously)", "27.18"),
    ("BUY ME a bag of resistors i'll never use", "12.34"),
    ("BUY ME a hammer for extremely light tapping", "9.99"),
    ("BUY ME a fax service subscription (fully ironic)", "40.40"),
    ("BUY ME a second-hand dentist chair (for vibes)", "21.00"),
    ("BUY ME a pallet of post-it notes (load-bearing)", "55.55"),
    ("BUY ME a server rack turned into furniture", "17.76"),
    (
        "BUY ME a certificate of authenticity for something fake",
        "22.22",
    ),
    ("BUY ME 1000 yards of bubble wrap (therapeutic)", "9.99"),
    (
        "BUY ME an expired globe (geopolitics not included)",
        "44.44",
    ),
    (
        "BUY ME a broken laptop that once belonged to a philosopher",
        "10.10",
    ),
    (
        "BUY ME a surplus military compass (true north only)",
        "33.33",
    ),
    (
        "BUY ME a commercial ice cream maker and no regrets",
        "12.34",
    ),
    (
        "BUY ME a decommissioned fire extinguisher (decorative)",
        "9.99",
    ),
    ("BUY ME a typewriter so i can feel things", "15.00"),
    ("BUY ME a glory hole kit (networking purposes)", "42.00"),
];

fn print_banner() {
    let ver = version::CLOAK_VERSION;
    eprintln!(
        "{}",
        format!("┌─ cloak v{ver} ─────────────────────────────────┐").cyan()
    );
    for line in BANNER.lines().skip(1) {
        eprintln!("{}", line.cyan().bold());
    }
    eprintln!();
    eprintln!(
        "  {}",
        "Protect .env secrets from AI coding agents".dimmed()
    );
    eprintln!();
    eprintln!("  {}", "Daniel Tamas".dimmed());
    eprintln!("  {}", "hello@danieltamas.com".dimmed());

    // Rotating support message
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let idx = (secs / 30) as usize % SUPPORT_MESSAGES.len();
    let (msg, price) = SUPPORT_MESSAGES[idx];
    eprintln!();
    eprintln!(
        "  {}",
        format!("{msg} — {price} USDC").truecolor(255, 20, 147)
    );
    eprintln!(
        "  {}",
        format!("→ dani.fkey.id/?amount={price}&token=USDC&chain=base")
            .truecolor(200, 16, 115)
            .underline()
    );
    eprintln!();
    eprintln!(
        "{}",
        "└─ © 2025 Daniel Tamas — danieltamas.com ────────┘".dimmed()
    );
    eprintln!();
}

#[derive(Parser)]
#[command(
    name = "cloak",
    version,
    about = "Protect .env secrets from AI coding agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize Cloak protection for a .env file
    Init,
    /// Edit the protected .env file with real values
    Edit,
    /// Run a command with real environment variables injected
    Run {
        /// Command and arguments to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Peek at real values without editing
    Peek,
    /// Set a single secret value
    Set {
        /// The key to set
        key: String,
        /// The value to set
        value: String,
    },
    /// Reveal the real value of a key
    Reveal {
        /// The key to reveal temporarily
        key: String,
        /// Duration in seconds to reveal (default 30)
        #[arg(long, default_value = "30")]
        duration: u64,
    },
    /// Remove Cloak protection
    Unprotect,
    /// Show protection status
    Status,
    /// Self-update Cloak to the latest version
    Update,
    /// Recover from a lost keychain using recovery key
    Recover,
}

fn main() {
    print_banner();
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Init => commands::init::run(),
        Commands::Recover => commands::recover::run(),
        Commands::Edit => commands::edit::run(),
        Commands::Run { command } => commands::run::run(command),
        Commands::Peek => commands::peek::run(),
        Commands::Set { key, value } => commands::set::run(key, value),
        Commands::Reveal { key, duration } => commands::reveal::run(key, duration),
        Commands::Unprotect => commands::unprotect::run(),
        Commands::Status => commands::status::run(),
        Commands::Update => commands::update::run(),
    }
}
