use std::path::PathBuf;

use clap::ValueEnum;

#[derive(clap::Parser)]
#[command(about, version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    #[arg(short, long, default_value_t = String::from("http://127.0.0.1:8080/api"))]
    pub url: String,
    #[arg(short, long, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
}

#[derive(clap::Subcommand, Debug)]
pub enum Commands {
    FullTest,
    TestRegister {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    TestLogin {
        #[arg(short, long)]
        input: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
#[value(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.to_ascii_uppercase();

        for variant in Self::value_variants() {
            if variant.to_possible_value().unwrap().matches(&s, false) {
                return Ok(*variant);
            }
        }
        Err(format!("Invalid log level: {s}."))
    }
}
