//! Switches of the root-cause round (following the caller through the
//! application's own layers, and counting a check only where its rejection
//! reaches the response). `ARCHER_RC=0` turns the whole round off;
//! `ARCHER_RC_<NAME>=0` turns one change off.

/// Whether the root-cause change `name` is on.
pub(crate) fn enabled(name: &str) -> bool {
    let on = |variable: String| std::env::var(variable).map_or(true, |value| value != "0");
    on("ARCHER_RC".to_string()) && on(format!("ARCHER_RC_{name}"))
}
