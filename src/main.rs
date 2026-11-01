use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod analyzer;

#[derive(Debug, Parser)]
#[command(
    name = "archer",
    version,
    about = "ARCHER — Actix-Web authorization drift prototype"
)]
struct Cli {
    /// Rust/Actix-Web repository to analyze
    path: PathBuf,

    /// Emit the report as JSON for programmatic consumers
    #[arg(long)]
    json: bool,

    /// Also scan tests/, examples/, and benches/ directories
    #[arg(long)]
    include_tests: bool,

    /// Minimum number of authorized peers before a peer group can produce findings
    #[arg(long, default_value_t = analyzer::AnalysisOptions::DEFAULT_MIN_SUPPORT,
          value_parser = parse_min_support)]
    min_support: usize,

    /// Minimum share of a peer group's routes that must be authorized, in (0, 1],
    /// before its unauthorized routes are reported
    #[arg(long, default_value_t = analyzer::AnalysisOptions::DEFAULT_DOMINANCE_THRESHOLD,
          value_parser = parse_threshold)]
    threshold: f64,
}

fn parse_min_support(value: &str) -> Result<usize, String> {
    match value.parse() {
        Ok(0) => Err("must be at least 1".into()),
        Ok(count) => Ok(count),
        Err(_) => Err(format!("`{value}` is not a whole number")),
    }
}

fn parse_threshold(value: &str) -> Result<f64, String> {
    let threshold: f64 = value
        .parse()
        .map_err(|_| format!("`{value}` is not a number"))?;
    if threshold > 0.0 && threshold <= 1.0 {
        Ok(threshold)
    } else {
        Err("must be greater than 0 and at most 1".into())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let options = analyzer::AnalysisOptions {
        include_tests: cli.include_tests,
        min_support: cli.min_support,
        dominance_threshold: cli.threshold,
    };
    let report = analyzer::analyze_repository_with(&cli.path, &options)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("ARCHER authorization analysis");
    println!("Repository: {}", cli.path.display());
    println!("Rust files scanned: {}", report.files_scanned);
    if !report.parse_errors.is_empty() {
        println!("Rust files skipped: {}", report.parse_errors.len());
        for error in &report.parse_errors {
            println!("  - {}", error);
        }
    }
    println!("Route candidates: {}", report.routes.len());
    println!();

    for route in &report.routes {
        println!("{} {}", route.method, route.path);
        if route.authorization.is_empty() {
            println!("  authorization:");
            println!("    ✗ No recognized authorization evidence");
        } else {
            println!("  authorization:");
            for evidence in &route.authorization {
                println!("    ✓ {:?}", evidence.kind);
                println!("      mechanism: {}", evidence.mechanism);
                println!(
                    "      symbol: {}",
                    evidence.symbol.as_deref().unwrap_or("<none>")
                );
                println!(
                    "      location: {}:{}",
                    evidence.file.display(),
                    evidence.line
                );
                println!(
                    "      handler: {}",
                    evidence.handler.as_deref().unwrap_or("<none>")
                );
                println!("      strength: {:?}", evidence.strength);
            }
        }
    }

    if !report.findings.is_empty() {
        println!("\nPotential authorization drift:");
        for finding in &report.findings {
            println!("{}", finding);
        }
    } else {
        println!("\nNo prototype drift findings.");
    }

    Ok(())
}
