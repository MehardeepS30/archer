//! Switches of the P13 round (known general gaps). `ARCHER_P13=0` turns the
//! whole round off; `ARCHER_P13_<NAME>=0` turns one change off.

/// Whether the P13 change `name` is on.
pub(crate) fn enabled(name: &str) -> bool {
    let on = |variable: String| std::env::var(variable).map_or(true, |value| value != "0");
    on("ARCHER_P13".to_string()) && on(format!("ARCHER_P13_{name}"))
}
