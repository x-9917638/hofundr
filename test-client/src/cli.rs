// Copyright (C) 2026 Valerie <valerie@ouppy.gay>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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
