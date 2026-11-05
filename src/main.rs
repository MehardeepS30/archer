use anyhow::Result;
use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

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

    /// Exit with status 1 when drift findings are reported (status 2 means
    /// the analysis itself failed)
    #[arg(long)]
    fail_on_findings: bool,

    /// Minimum number of authorized peers before a peer group can produce findings
    #[arg(long, default_value_t = analyzer::AnalysisOptions::DEFAULT_MIN_SUPPORT,
          value_parser = parse_min_support)]
    min_support: usize,

    /// Minimum share of a peer group's routes that must be authorized, in (0, 1],
    /// before its unauthorized routes are reported
    #[arg(long, default_value_t = analyzer::AnalysisOptions::DEFAULT_DOMINANCE_THRESHOLD,
          value_parser = parse_threshold)]
    threshold: f64,

    /// Reviewer decisions to apply (public routes, dismissed findings);
    /// defaults to archer.toml at the repository root when it exists
    #[arg(long)]
    config: Option<PathBuf>,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(has_findings) if has_findings && cli.fail_on_findings => ExitCode::from(1),
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// Analyzes and prints the report; returns whether there are findings.
fn run(cli: &Cli) -> Result<bool> {
    let options = analyzer::AnalysisOptions {
        include_tests: cli.include_tests,
        min_support: cli.min_support,
        dominance_threshold: cli.threshold,
        config_file: cli.config.clone(),
    };
    let report = analyzer::analyze_repository_with(&cli.path, &options)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(!report.finding_details.is_empty());
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
    let coverage = &report.coverage;
    println!(
        "Handler coverage: {} of {} functions that look like handlers are routed",
        coverage.routed_handlers, coverage.likely_handlers
    );
    if coverage.unresolved_handlers > 0 || coverage.unresolved_paths > 0 {
        println!(
            "  routes with unresolved handlers: {}; with unresolved paths: {}",
            coverage.unresolved_handlers, coverage.unresolved_paths
        );
    }
    for warning in &report.warnings {
        println!("Warning: {warning}");
    }
    println!();

    for route in &report.routes {
        println!("{} {}", route.method, route.path);
        if route.authorization.is_empty() {
            println!("  authorization:");
            println!("    ✗ No recognized authorization evidence");
        } else {
            println!("  authorization:");
            for evidence in &route.authorization {
                println!("    ✓ {}", evidence.kind);
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
                println!("      strength: {}", evidence.strength);
            }
        }
    }

    if !report.finding_details.is_empty() {
        println!("\nPotential authorization drift:");
        for finding in &report.finding_details {
            println!("{}", analyzer::format_finding(finding));
        }
    } else {
        println!("\nNo prototype drift findings.");
    }
    if let Some(config) = &report.config {
        let public = report
            .unjudged
            .iter()
            .filter(|route| route.reason == analyzer::UnjudgedReason::DeclaredPublic)
            .count();
        println!(
            "\n{}: {} route(s) declared public, {} finding(s) dismissed",
            config.display(),
            public,
            report.dismissed.len()
        );
        for dismissed in &report.dismissed {
            println!(
                "  dismissed: {} {} ({}): {}",
                dismissed.finding.suspicious_route.method,
                dismissed.finding.suspicious_route.path,
                dismissed.finding.category,
                dismissed.reason
            );
        }
    }

    Ok(!report.finding_details.is_empty())
}
