//! Evaluates a route path that is built in code rather than written as a
//! literal: `format!` and `concat!`, `.replace(..)`, `let` values, constant
//! route tables (`ROUTES.auth.login`), and calls to the project's own
//! functions with their arguments bound (`cfg_path("/info/quota")`). The
//! parts it cannot know (a runtime setting, a function parameter) stay in
//! the path as `<unresolved:text>` segments, so the rest of the path still
//! places the route.

use std::{
    collections::HashMap,
    path::Path,
};

use quote::ToTokens;
use syn::{Expr, ExprLit, FnArg, Lit, Pat, Stmt, punctuated::Punctuated};

use super::handlers::{HandlerIndex, ModuleKey, UsePath};
use super::routes::{BlockScope, HandlerTarget};
use super::model::HandlerResolution;

/// Whether path evaluation runs; ARCHER_P7=0 turns it off.
pub(crate) fn enabled() -> bool {
    std::env::var("ARCHER_P7").map_or(true, |value| value != "0")
}

/// Calls followed into the project's functions, at most.
const MAX_DEPTH: usize = 6;
/// Expressions evaluated for one path, at most.
const MAX_STEPS: usize = 4000;

#[derive(Debug, Clone)]
pub(crate) enum Value {
    Str(String),
    /// A struct value, as a route table's fields.
    Fields(Vec<(String, Value)>),
    /// A part that is not known statically, by its source text.
    Unknown(String),
}

impl Value {
    /// The value as path text: an unknown part as one `<unresolved:..>`
    /// segment.
    fn text(&self) -> String {
        match self {
            Value::Str(text) => text.clone(),
            Value::Unknown(text) => format!("<unresolved:{text}>"),
            Value::Fields(_) => "<unresolved:value>".to_owned(),
        }
    }
}

/// The short form of an expression kept inside an `<unresolved:..>`
/// segment: no spaces and none of `&/<>{}`, so it never splits the path.
pub(crate) fn segment_text(expr: &Expr) -> String {
    let text: String = expr
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace() && !"&/<>{}".contains(*character))
        .take(48)
        .collect();
    if text.is_empty() { "expression".to_owned() } else { text }
}

/// Where names are looked up while evaluating.
enum Names<'f> {
    /// At a route site: the visitor's block scopes and loop values.
    Visitor {
        scopes: &'f [BlockScope],
        loop_values: &'f [(String, String)],
    },
    /// Inside a called function: its parameters and `let` values.
    Env(&'f HashMap<String, Value>),
}

struct Frame<'f> {
    crate_key: &'f Path,
    module: &'f [String],
    owner: Option<&'f str>,
    names: Names<'f>,
}

pub(crate) struct Evaluator<'i, 'a> {
    index: &'i HandlerIndex<'a>,
    steps: usize,
    depth: usize,
}

/// Evaluates `expr` as written at a route site.
pub(crate) fn evaluate_at_site(
    index: &HandlerIndex<'_>,
    crate_key: &Path,
    module: &[String],
    scopes: &[BlockScope],
    loop_values: &[(String, String)],
    expr: &Expr,
) -> Value {
    let frame = Frame {
        crate_key,
        module,
        owner: None,
        names: Names::Visitor { scopes, loop_values },
    };
    Evaluator { index, steps: 0, depth: 0 }.eval(&frame, expr)
}

impl Evaluator<'_, '_> {
    fn eval(&mut self, frame: &Frame<'_>, expr: &Expr) -> Value {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return Value::Unknown(segment_text(expr));
        }
        match expr {
            Expr::Lit(ExprLit { lit, .. }) => match lit {
                Lit::Str(value) => Value::Str(value.value()),
                Lit::Char(value) => Value::Str(value.value().to_string()),
                Lit::Int(value) => Value::Str(value.base10_digits().to_owned()),
                _ => Value::Unknown(segment_text(expr)),
            },
            Expr::Reference(reference) => self.eval(frame, &reference.expr),
            Expr::Paren(paren) => self.eval(frame, &paren.expr),
            Expr::Group(group) => self.eval(frame, &group.expr),
            Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
                self.eval(frame, &unary.expr)
            }
            Expr::Block(block) if block.label.is_none() => self.eval_block(frame, &block.block.stmts),
            Expr::Path(path) if path.qself.is_none() => self.eval_path(frame, &path.path, expr),
            Expr::Field(field) => {
                let syn::Member::Named(name) = &field.member else {
                    return Value::Unknown(segment_text(expr));
                };
                match self.eval(frame, &field.base) {
                    Value::Fields(fields) => fields
                        .into_iter()
                        .find(|(field, _)| name == field)
                        .map_or_else(|| Value::Unknown(segment_text(expr)), |(_, value)| value),
                    _ => Value::Unknown(segment_text(expr)),
                }
            }
            Expr::Struct(literal) if literal.qself.is_none() => {
                let mut fields = Vec::new();
                for field in &literal.fields {
                    if let syn::Member::Named(name) = &field.member {
                        fields.push((name.to_string(), self.eval(frame, &field.expr)));
                    }
                }
                Value::Fields(fields)
            }
            Expr::Macro(mac) => self.eval_macro(frame, &mac.mac, expr),
            Expr::MethodCall(call) => self.eval_method(frame, call, expr),
            Expr::Call(call) => self.eval_call(frame, call, expr),
            _ => Value::Unknown(segment_text(expr)),
        }
    }

    fn eval_path(&mut self, frame: &Frame<'_>, path: &syn::Path, expr: &Expr) -> Value {
        let segments: Vec<String> = path.segments.iter().map(|segment| segment.ident.to_string()).collect();
        if let [name] = segments.as_slice() {
            match &frame.names {
                Names::Env(env) => {
                    if let Some(value) = env.get(name) {
                        return value.clone();
                    }
                }
                Names::Visitor { scopes, loop_values } => {
                    if let Some((_, value)) = loop_values.iter().rev().find(|(bound, _)| bound == name) {
                        return Value::Str(value.clone());
                    }
                    for scope in scopes.iter().rev() {
                        if let Some(value) = scope.values.get(name) {
                            return value.clone();
                        }
                        if scope.locals.contains(name) || scope.items.contains_key(name) {
                            return Value::Unknown(segment_text(expr));
                        }
                    }
                }
            }
        }
        if let Some(value) = self.index.resolve_const(frame.crate_key, frame.module, &segments) {
            return Value::Str(value);
        }
        if self.depth < MAX_DEPTH
            && let Some(((crate_key, module), value)) =
                self.index.resolve_const_expr(frame.crate_key, frame.module, &segments)
        {
            let env = HashMap::new();
            let inner = Frame {
                crate_key: &crate_key,
                module: &module,
                owner: None,
                names: Names::Env(&env),
            };
            self.depth += 1;
            let value = self.eval(&inner, value);
            self.depth -= 1;
            return value;
        }
        Value::Unknown(segment_text(expr))
    }

    fn eval_block(&mut self, frame: &Frame<'_>, statements: &[Stmt]) -> Value {
        let mut env = match &frame.names {
            Names::Env(env) => (*env).clone(),
            Names::Visitor { .. } => HashMap::new(),
        };
        for (position, statement) in statements.iter().enumerate() {
            let inner = Frame {
                crate_key: frame.crate_key,
                module: frame.module,
                owner: frame.owner,
                names: match &frame.names {
                    Names::Visitor { scopes, loop_values } if env.is_empty() => {
                        Names::Visitor { scopes, loop_values }
                    }
                    _ => Names::Env(&env),
                },
            };
            match statement {
                Stmt::Local(local) => {
                    let Some(name) = simple_name(&local.pat) else {
                        return Value::Unknown("block".to_owned());
                    };
                    let value = match &local.init {
                        Some(init) if init.diverge.is_none() => self.eval(&inner, &init.expr),
                        _ => Value::Unknown(name.clone()),
                    };
                    env.insert(name, value);
                }
                Stmt::Expr(Expr::Return(returned), _) => {
                    return match &returned.expr {
                        Some(value) => self.eval(&inner, value),
                        None => Value::Unknown("block".to_owned()),
                    };
                }
                Stmt::Expr(tail, None) if position + 1 == statements.len() => {
                    return self.eval(&inner, tail);
                }
                Stmt::Macro(mac) if mac.semi_token.is_none() && position + 1 == statements.len() => {
                    let expr = Expr::Macro(syn::ExprMacro {
                        attrs: Vec::new(),
                        mac: mac.mac.clone(),
                    });
                    return self.eval(&inner, &expr);
                }
                Stmt::Item(_) => {}
                _ => return Value::Unknown("block".to_owned()),
            }
        }
        Value::Unknown("block".to_owned())
    }

    fn eval_macro(&mut self, frame: &Frame<'_>, mac: &syn::Macro, expr: &Expr) -> Value {
        let name = mac.path.segments.last().map(|segment| segment.ident.to_string());
        let Ok(arguments) = mac.parse_body_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated) else {
            return Value::Unknown(segment_text(expr));
        };
        let arguments: Vec<Expr> = arguments.into_iter().collect();
        match name.as_deref() {
            Some("concat") => Value::Str(
                arguments
                    .iter()
                    .map(|argument| self.eval(frame, argument).text())
                    .collect(),
            ),
            Some("format") => {
                let Some((Expr::Lit(ExprLit { lit: Lit::Str(template), .. }), rest)) = arguments.split_first() else {
                    return Value::Unknown(segment_text(expr));
                };
                let mut positional = Vec::new();
                let mut named = HashMap::new();
                for argument in rest {
                    match argument {
                        Expr::Assign(assign) => {
                            if let Expr::Path(left) = &*assign.left
                                && let Some(ident) = left.path.get_ident()
                            {
                                named.insert(ident.to_string(), &*assign.right);
                            }
                        }
                        other => positional.push(other),
                    }
                }
                match self.format(frame, &template.value(), &positional, &named) {
                    Some(text) => Value::Str(text),
                    None => Value::Unknown(segment_text(expr)),
                }
            }
            _ => Value::Unknown(segment_text(expr)),
        }
    }

    /// A `format!` template with its arguments filled in. `None` for a
    /// placeholder it cannot read.
    fn format(
        &mut self,
        frame: &Frame<'_>,
        template: &str,
        positional: &[&Expr],
        named: &HashMap<String, &Expr>,
    ) -> Option<String> {
        let mut out = String::new();
        let mut next = 0;
        let mut characters = template.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '{' if characters.peek() == Some(&'{') => {
                    characters.next();
                    out.push('{');
                }
                '}' if characters.peek() == Some(&'}') => {
                    characters.next();
                    out.push('}');
                }
                '{' => {
                    let mut placeholder = String::new();
                    loop {
                        match characters.next()? {
                            '}' => break,
                            other => placeholder.push(other),
                        }
                    }
                    let (argument, spec) = placeholder.split_once(':').unwrap_or((&placeholder, ""));
                    // `{:?}` quotes a string; widths and the like change it.
                    if !spec.is_empty() {
                        return None;
                    }
                    let argument = argument.trim();
                    let value = if argument.is_empty() {
                        let expr = positional.get(next)?;
                        next += 1;
                        self.eval(frame, expr)
                    } else if let Ok(position) = argument.parse::<usize>() {
                        self.eval(frame, positional.get(position)?)
                    } else if let Some(expr) = named.get(argument) {
                        self.eval(frame, expr)
                    } else {
                        // `format!("/v1/{mount}")` captures `mount`.
                        let captured: Expr = syn::parse_str(argument).ok()?;
                        self.eval(frame, &captured)
                    };
                    out.push_str(&value.text());
                }
                other => out.push(other),
            }
        }
        Some(out)
    }

    fn eval_method(&mut self, frame: &Frame<'_>, call: &syn::ExprMethodCall, expr: &Expr) -> Value {
        let method = call.method.to_string();
        match method.as_str() {
            "to_string" | "to_owned" | "as_str" | "into" | "clone" | "as_ref" | "borrow" | "deref"
                if call.args.is_empty() =>
            {
                self.eval(frame, &call.receiver)
            }
            "replace" | "replacen" => {
                let receiver = self.eval(frame, &call.receiver);
                let (Value::Str(text), Some(from), Some(to)) = (&receiver, call.args.first(), call.args.get(1)) else {
                    return Value::Unknown(segment_text(expr));
                };
                let (Value::Str(from), Value::Str(to)) = (self.eval(frame, from), self.eval(frame, to)) else {
                    return Value::Unknown(segment_text(expr));
                };
                if method == "replacen" {
                    let Some(Value::Str(count)) = call.args.get(2).map(|count| self.eval(frame, count)) else {
                        return Value::Unknown(segment_text(expr));
                    };
                    let Ok(count) = count.parse::<usize>() else {
                        return Value::Unknown(segment_text(expr));
                    };
                    Value::Str(text.replacen(&from, &to, count))
                } else {
                    Value::Str(text.replace(&from, &to))
                }
            }
            "trim_end_matches" | "trim_start_matches" => {
                let receiver = self.eval(frame, &call.receiver);
                let (Value::Str(text), Some(pattern)) = (&receiver, call.args.first()) else {
                    return Value::Unknown(segment_text(expr));
                };
                let Value::Str(pattern) = self.eval(frame, pattern) else {
                    return Value::Unknown(segment_text(expr));
                };
                if pattern.is_empty() {
                    return receiver;
                }
                Value::Str(if method == "trim_end_matches" {
                    text.trim_end_matches(pattern.as_str()).to_owned()
                } else {
                    text.trim_start_matches(pattern.as_str()).to_owned()
                })
            }
            _ => Value::Unknown(segment_text(expr)),
        }
    }

    fn eval_call(&mut self, frame: &Frame<'_>, call: &syn::ExprCall, expr: &Expr) -> Value {
        let Expr::Path(function) = &*call.func else {
            return Value::Unknown(segment_text(expr));
        };
        if function.qself.is_some() || self.depth >= MAX_DEPTH {
            return Value::Unknown(segment_text(expr));
        }
        let segments: Vec<String> = function
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        // `String::from("/a")` and the like keep the string.
        if let [ty, constructor] = segments.as_slice()
            && matches!(ty.as_str(), "String" | "Cow" | "Box" | "Rc" | "Arc")
            && matches!(constructor.as_str(), "from" | "new" | "Borrowed" | "Owned")
            && let [argument] = call.args.iter().collect::<Vec<_>>().as_slice()
        {
            return self.eval(frame, argument);
        }
        let Some(definition) = self.callee(frame, &segments, function.path.leading_colon.is_some()) else {
            return Value::Unknown(segment_text(expr));
        };
        let function_item = &self.index.items[definition];
        let mut env = HashMap::new();
        let mut arguments = call.args.iter();
        for input in &function_item.sig.inputs {
            let FnArg::Typed(parameter) = input else {
                continue;
            };
            let Some(argument) = arguments.next() else {
                return Value::Unknown(segment_text(expr));
            };
            let value = self.eval(frame, argument);
            if let Some(name) = simple_name(&parameter.pat) {
                env.insert(name, value);
            }
        }
        let callee = &self.index.definitions[definition];
        let inner = Frame {
            crate_key: &callee.crate_key,
            module: &callee.module,
            owner: callee.owner.as_deref(),
            names: Names::Env(&env),
        };
        self.depth += 1;
        let value = self.eval_block(&inner, &function_item.block.stmts);
        self.depth -= 1;
        match value {
            Value::Unknown(_) => Value::Unknown(segment_text(expr)),
            known => known,
        }
    }

    /// The project function a call names: a free function by Rust's
    /// scoping rules, or an associated function of a type (`Auth::new`,
    /// `Self::new`) whose `impl` is in the module the type resolves to.
    fn callee(&self, frame: &Frame<'_>, segments: &[String], leading_colon: bool) -> Option<usize> {
        let (name, qualifier) = segments.split_last()?;
        if let Some(ty) = qualifier.last()
            && (ty == "Self" || ty.starts_with(char::is_uppercase))
        {
            let (type_name, type_module) = self.type_module(frame, qualifier)?;
            let candidates = self.index.methods.get(&(type_name, name.clone()))?;
            let in_module: Vec<usize> = candidates
                .iter()
                .copied()
                .filter(|&index| {
                    let definition = &self.index.definitions[index];
                    definition.crate_key == type_module.0 && definition.module == type_module.1
                })
                .collect();
            return match (in_module.as_slice(), candidates.as_slice()) {
                ([index], _) | ([], [index]) => Some(*index),
                _ => None,
            };
        }
        let target = HandlerTarget::Path {
            segments: segments.to_vec(),
            leading_colon,
        };
        match self.index.resolve_handler_index(frame.crate_key, frame.module, &target) {
            (Some(index), resolution)
                if !matches!(resolution, HandlerResolution::UniqueName)
                    && self.index.definitions[index].owner.is_none() =>
            {
                Some(index)
            }
            _ => None,
        }
    }

    /// A type path's name and the module it is defined in, as written in
    /// the frame's module.
    fn type_module(&self, frame: &Frame<'_>, path: &[String]) -> Option<(String, ModuleKey)> {
        let here = || (frame.crate_key.to_path_buf(), frame.module.to_vec());
        match path {
            [ty] if ty == "Self" => Some((frame.owner?.to_owned(), here())),
            [ty] => {
                let imports = self
                    .index
                    .scope(frame.crate_key, frame.module)
                    .and_then(|scope| scope.imports.get(ty));
                match imports.map(Vec::as_slice) {
                    Some([import]) => {
                        let (original, prefix) = import.segments.split_last()?;
                        let prefix = UsePath {
                            segments: prefix.to_vec(),
                            leading_colon: import.leading_colon,
                        };
                        let module = self.index.resolve_module(frame.crate_key, frame.module, &prefix, 0)?;
                        Some((original.clone(), module))
                    }
                    Some(_) => None,
                    None => Some((ty.clone(), here())),
                }
            }
            [qualifier @ .., ty] => {
                let qualifier = UsePath {
                    segments: qualifier.to_vec(),
                    leading_colon: false,
                };
                let module = self.index.resolve_module(frame.crate_key, frame.module, &qualifier, 0)?;
                Some((ty.clone(), module))
            }
            [] => None,
        }
    }
}

fn simple_name(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Ident(ident) if ident.subpat.is_none() => Some(ident.ident.to_string()),
        Pat::Type(typed) => simple_name(&typed.pat),
        _ => None,
    }
}

/// The value a `let` binding at a route site holds, for later path
/// arguments that name it. Only strings and struct values are kept.
pub(crate) fn binding_value(
    index: &HandlerIndex<'_>,
    crate_key: &Path,
    module: &[String],
    scopes: &[BlockScope],
    loop_values: &[(String, String)],
    local: &syn::Local,
) -> Option<(String, Value)> {
    let name = simple_name(&local.pat)?;
    let init = local.init.as_ref().filter(|init| init.diverge.is_none())?;
    if !could_be_path(&init.expr) {
        return None;
    }
    match evaluate_at_site(index, crate_key, module, scopes, loop_values, &init.expr) {
        Value::Unknown(_) => None,
        value => Some((name, value)),
    }
}

/// Whether an initializer is the kind of expression a path is built from,
/// so that builder chains and other values are not evaluated.
fn could_be_path(expr: &Expr) -> bool {
    match expr {
        Expr::Lit(ExprLit { lit: Lit::Str(_), .. }) | Expr::Macro(_) | Expr::Field(_) | Expr::Call(_) => true,
        Expr::Path(path) => path.qself.is_none(),
        Expr::Reference(reference) => could_be_path(&reference.expr),
        Expr::Paren(paren) => could_be_path(&paren.expr),
        Expr::MethodCall(call) => matches!(
            call.method.to_string().as_str(),
            "to_string" | "to_owned" | "as_str" | "into" | "clone" | "replace" | "replacen"
                | "trim_end_matches" | "trim_start_matches"
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(source: &str, expr: &str) -> String {
        let file: syn::File = syn::parse_str(source).expect("source parses");
        let path = Path::new("main.rs");
        let index = HandlerIndex::single_file(path, &file);
        let expr: Expr = syn::parse_str(expr).expect("expression parses");
        evaluate_at_site(&index, path, &[], &[], &[], &expr).text()
    }

    #[test]
    fn format_and_concat_fill_in_what_is_known() {
        let source = r#"const V: &str = "3"; fn base(p: &str) -> String { format!("/v{V}{}", p.trim_end_matches('/')) }"#;
        assert_eq!(evaluate(source, r#"format!("/{}/{{id:{}}}", V, "[0-9]+")"#), "/3/{id:[0-9]+}");
        assert_eq!(evaluate(source, r#"concat!("/v", 1, "/x")"#), "/v1/x");
        assert_eq!(evaluate(source, r#"base("/items/")"#), "/v3/items");
        assert_eq!(evaluate(source, r#"format!("/{}/x", cfg.prefix)"#), "/<unresolved:cfg.prefix>/x");
        // `{:?}` would quote the string: not a path.
        assert_eq!(evaluate(source, r#"format!("/{:?}", V)"#), r#"<unresolved:format!(":?",V)>"#);
        assert_eq!(evaluate(source, r#""/a/b".replace("b", "c").to_string()"#), "/a/c");
    }
}
