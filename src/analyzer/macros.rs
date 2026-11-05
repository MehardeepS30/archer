//! A small `macro_rules!` expander, so that routes a project registers
//! through its own declarative macros are read like the code the macro
//! produces. It supports the matcher forms route helpers use: fragments
//! (`$p:expr`, `$h:path`, `$n:ident`, `$l:literal`, `$t:tt`, ...), literal
//! tokens, delimited groups, and one or more nested `$( ... ) sep op`
//! repetitions. A rule it cannot match is skipped; an invocation no rule
//! matches is left unexpanded.

use proc_macro2::{Delimiter, Group, Spacing, TokenStream, TokenTree};
use std::collections::HashMap;

/// One `matcher => transcriber` rule.
#[derive(Clone)]
pub(crate) struct Rule {
    matcher: Vec<Pattern>,
    transcriber: TokenStream,
}

#[derive(Clone)]
enum Pattern {
    /// A token that must appear as written, compared by its text.
    Token(String),
    Fragment(String, String),
    Group(Delimiter, Vec<Pattern>),
    Repeat(Vec<Pattern>, Option<String>, char),
}

#[derive(Clone, Debug)]
enum Binding {
    One(TokenStream),
    Many(Vec<Binding>),
}

/// The rules of a `macro_rules! name { ... }` body.
pub(crate) fn parse_rules(body: &TokenStream) -> Vec<Rule> {
    let tokens: Vec<TokenTree> = body.clone().into_iter().collect();
    let mut rules = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        // matcher group, `=>`, transcriber group, optional `;`
        let (Some(TokenTree::Group(matcher)), Some(TokenTree::Punct(eq)), Some(TokenTree::Punct(gt)), Some(TokenTree::Group(transcriber))) = (
            tokens.get(index),
            tokens.get(index + 1),
            tokens.get(index + 2),
            tokens.get(index + 3),
        ) else {
            break;
        };
        if eq.as_char() != '=' || gt.as_char() != '>' {
            break;
        }
        let matcher_tokens: Vec<TokenTree> = matcher.stream().into_iter().collect();
        if let Some(matcher) = parse_matcher(&matcher_tokens) {
            rules.push(Rule {
                matcher,
                transcriber: transcriber.stream(),
            });
        }
        index += 4;
        if matches!(tokens.get(index), Some(TokenTree::Punct(p)) if p.as_char() == ';') {
            index += 1;
        }
    }
    rules
}

fn parse_matcher(tokens: &[TokenTree]) -> Option<Vec<Pattern>> {
    let mut patterns = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            TokenTree::Punct(dollar) if dollar.as_char() == '$' => match tokens.get(index + 1)? {
                TokenTree::Ident(name) => {
                    let colon = tokens.get(index + 2);
                    let fragment = tokens.get(index + 3);
                    match (colon, fragment) {
                        (Some(TokenTree::Punct(colon)), Some(TokenTree::Ident(fragment)))
                            if colon.as_char() == ':' =>
                        {
                            patterns.push(Pattern::Fragment(name.to_string(), fragment.to_string()));
                            index += 4;
                        }
                        _ => return None,
                    }
                }
                TokenTree::Group(group) if group.delimiter() == Delimiter::Parenthesis => {
                    let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                    let inner = parse_matcher(&inner)?;
                    index += 2;
                    let (separator, op) = repetition_suffix(tokens, &mut index)?;
                    patterns.push(Pattern::Repeat(inner, separator, op));
                }
                _ => return None,
            },
            TokenTree::Group(group) => {
                let inner: Vec<TokenTree> = group.stream().into_iter().collect();
                patterns.push(Pattern::Group(group.delimiter(), parse_matcher(&inner)?));
                index += 1;
            }
            other => {
                patterns.push(Pattern::Token(other.to_string()));
                index += 1;
            }
        }
    }
    Some(patterns)
}

/// The `sep? op` after a `$( ... )` group, advancing `index` past it.
fn repetition_suffix(tokens: &[TokenTree], index: &mut usize) -> Option<(Option<String>, char)> {
    let is_op = |token: Option<&TokenTree>| match token {
        Some(TokenTree::Punct(p)) if matches!(p.as_char(), '*' | '+' | '?') => Some(p.as_char()),
        _ => None,
    };
    if let Some(op) = is_op(tokens.get(*index)) {
        *index += 1;
        return Some((None, op));
    }
    let separator = tokens.get(*index)?.to_string();
    let op = is_op(tokens.get(*index + 1))?;
    *index += 2;
    Some((Some(separator), op))
}

/// Expands an invocation with the first rule that matches its input.
pub(crate) fn expand(rules: &[Rule], input: &TokenStream) -> Option<TokenStream> {
    let input: Vec<TokenTree> = input.clone().into_iter().collect();
    rules.iter().find_map(|rule| {
        let mut bindings = HashMap::new();
        let used = match_sequence(&rule.matcher, &input, None, &mut bindings)?;
        (used == input.len()).then(|| transcribe(&rule.transcriber, &bindings))
    })
}

/// Matches `patterns` at the start of `input`, returning how many tokens it
/// used. `stop` is a token text that ends a greedy fragment when nothing in
/// `patterns` follows it (a repetition's separator).
fn match_sequence(
    patterns: &[Pattern],
    input: &[TokenTree],
    stop: Option<&str>,
    bindings: &mut HashMap<String, Binding>,
) -> Option<usize> {
    let mut position = 0;
    for (index, pattern) in patterns.iter().enumerate() {
        match pattern {
            Pattern::Token(text) => {
                if input.get(position)?.to_string() != *text {
                    return None;
                }
                position += 1;
            }
            Pattern::Group(delimiter, inner) => {
                let TokenTree::Group(group) = input.get(position)? else {
                    return None;
                };
                if group.delimiter() != *delimiter {
                    return None;
                }
                let tokens: Vec<TokenTree> = group.stream().into_iter().collect();
                if match_sequence(inner, &tokens, None, bindings)? != tokens.len() {
                    return None;
                }
                position += 1;
            }
            Pattern::Fragment(name, fragment) => {
                let single = matches!(fragment.as_str(), "ident" | "literal" | "lifetime" | "tt" | "block");
                let length = if single {
                    if position >= input.len() {
                        return None;
                    }
                    // A negative literal is two tokens.
                    let negative = fragment == "literal"
                        && matches!(&input[position], TokenTree::Punct(p) if p.as_char() == '-');
                    if negative || fragment == "lifetime" {
                        2
                    } else {
                        1
                    }
                } else {
                    let next = patterns[index + 1..].iter().find_map(|next| match next {
                        Pattern::Token(text) => Some(text.as_str()),
                        _ => None,
                    });
                    let end = next.or(if index + 1 == patterns.len() { stop } else { None });
                    greedy_length(&input[position..], end)
                };
                if length == 0 || position + length > input.len() {
                    return None;
                }
                let tokens: TokenStream = input[position..position + length].iter().cloned().collect();
                bindings.insert(name.clone(), Binding::One(tokens));
                position += length;
            }
            Pattern::Repeat(inner, separator, op) => {
                let mut iterations: Vec<HashMap<String, Binding>> = Vec::new();
                loop {
                    if *op == '?' && !iterations.is_empty() {
                        break;
                    }
                    let mut start = position;
                    if !iterations.is_empty()
                        && let Some(separator) = separator
                    {
                        match input.get(start) {
                            Some(token) if token.to_string() == *separator => start += 1,
                            _ => break,
                        }
                    }
                    if start >= input.len() {
                        break;
                    }
                    let mut found = HashMap::new();
                    let inner_stop = separator.as_deref().or(stop);
                    match match_sequence(inner, &input[start..], inner_stop, &mut found) {
                        Some(used) if used > 0 => {
                            position = start + used;
                            iterations.push(found);
                        }
                        _ => break,
                    }
                }
                if *op == '+' && iterations.is_empty() {
                    return None;
                }
                for name in pattern_names(inner) {
                    let values = iterations
                        .iter()
                        .map(|found| found.get(&name).cloned().unwrap_or(Binding::Many(Vec::new())))
                        .collect();
                    bindings.insert(name, Binding::Many(values));
                }
            }
        }
    }
    Some(position)
}

/// Tokens a greedy fragment takes: up to `end`, or to the end of input.
fn greedy_length(input: &[TokenTree], end: Option<&str>) -> usize {
    match end {
        Some(end) => input
            .iter()
            .position(|token| token.to_string() == end)
            .unwrap_or(input.len()),
        None => input.len(),
    }
}

fn pattern_names(patterns: &[Pattern]) -> Vec<String> {
    let mut names = Vec::new();
    for pattern in patterns {
        match pattern {
            Pattern::Fragment(name, _) => names.push(name.clone()),
            Pattern::Group(_, inner) | Pattern::Repeat(inner, _, _) => names.extend(pattern_names(inner)),
            Pattern::Token(_) => {}
        }
    }
    names
}

fn transcribe(tokens: &TokenStream, bindings: &HashMap<String, Binding>) -> TokenStream {
    let tokens: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let mut output = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        match &tokens[index] {
            TokenTree::Punct(dollar) if dollar.as_char() == '$' => match tokens.get(index + 1) {
                Some(TokenTree::Ident(name)) if name == "crate" => {
                    output.push(TokenTree::Ident(proc_macro2::Ident::new("crate", name.span())));
                    index += 2;
                }
                Some(TokenTree::Ident(name)) => {
                    match bindings.get(&name.to_string()) {
                        // A fragment keeps its grouping, as `$e * 2` does in Rust.
                        Some(Binding::One(value)) => {
                            let mut tokens = value.clone().into_iter();
                            match (tokens.next(), tokens.next()) {
                                (Some(single), None) => output.push(single),
                                _ => output.push(TokenTree::Group(Group::new(
                                    Delimiter::None,
                                    value.clone(),
                                ))),
                            }
                        }
                        _ => output.push(TokenTree::Ident(name.clone())),
                    }
                    index += 2;
                }
                Some(TokenTree::Group(group)) if group.delimiter() == Delimiter::Parenthesis => {
                    index += 2;
                    let (separator, _) =
                        repetition_suffix(&tokens, &mut index).unwrap_or((None, '*'));
                    let body = group.stream();
                    let names = stream_names(&body);
                    let count = names
                        .iter()
                        .filter_map(|name| match bindings.get(name) {
                            Some(Binding::Many(values)) => Some(values.len()),
                            _ => None,
                        })
                        .max()
                        .unwrap_or(0);
                    for iteration in 0..count {
                        if iteration > 0
                            && let Some(separator) = &separator
                        {
                            output.extend(separator_tokens(separator));
                        }
                        let mut local = bindings.clone();
                        for name in &names {
                            if let Some(Binding::Many(values)) = bindings.get(name)
                                && let Some(value) = values.get(iteration)
                            {
                                local.insert(name.clone(), value.clone());
                            }
                        }
                        output.extend(transcribe(&body, &local));
                    }
                }
                _ => {
                    output.push(tokens[index].clone());
                    index += 1;
                }
            },
            TokenTree::Group(group) => {
                let mut copy = Group::new(group.delimiter(), transcribe(&group.stream(), bindings));
                copy.set_span(group.span());
                output.push(TokenTree::Group(copy));
                index += 1;
            }
            other => {
                output.push(other.clone());
                index += 1;
            }
        }
    }
    output.into_iter().collect()
}

fn separator_tokens(separator: &str) -> Vec<TokenTree> {
    separator
        .parse::<TokenStream>()
        .map(|stream| stream.into_iter().collect())
        .unwrap_or_else(|_| {
            vec![TokenTree::Punct(proc_macro2::Punct::new(',', Spacing::Alone))]
        })
}

/// The `$name` variables a transcriber body uses.
fn stream_names(tokens: &TokenStream) -> Vec<String> {
    let tokens: Vec<TokenTree> = tokens.clone().into_iter().collect();
    let mut names = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Punct(dollar) if dollar.as_char() == '$' => {
                if let Some(TokenTree::Ident(name)) = tokens.get(index + 1) {
                    names.push(name.to_string());
                }
            }
            TokenTree::Group(group) => names.extend(stream_names(&group.stream())),
            _ => {}
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(definition: &str, invocation: &str) -> Option<String> {
        let rules = parse_rules(&definition.parse().unwrap());
        expand(&rules, &invocation.parse().unwrap()).map(|tokens| {
            syn::parse2::<syn::Expr>(tokens.clone())
                .map(|expr| quote::ToTokens::to_token_stream(&expr).to_string())
                .unwrap_or_else(|_| tokens.to_string())
        })
    }

    #[test]
    fn expands_fragments_and_repetitions() {
        let simple = run(
            "($p:expr, $h:path) => { web::resource($p).route(web::get().to($h)) };",
            "\"/a\", handlers::a",
        )
        .unwrap();
        assert!(simple.contains("\"/a\"") && simple.contains("handlers :: a"), "{simple}");

        let repeated = run(
            "($c:ident; $($p:literal => $h:ident),* $(,)?) => { $( $c.route($p, web::get().to($h)); )* };",
            "cfg; \"/a\" => a, \"/b\" => b,",
        )
        .unwrap();
        assert!(repeated.contains("\"/a\"") && repeated.contains("\"/b\""), "{repeated}");
        assert_eq!(repeated.matches("route").count(), 2, "{repeated}");

        // No rule matches: not expanded.
        assert!(run("($p:literal) => { $p };", "a, b").is_none());
    }
}
