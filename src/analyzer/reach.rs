//! Whether a check's rejection reaches the response.
//!
//! A helper's check protects a route only if the route lets its failure
//! through. Two ways it does not are read here, from the calling code:
//!
//! - the caller discards the failure: `match authorize(&req) { Ok(s) =>
//!   Some(s), Err(_) => None }`, `authorize(&req).ok()`, `if let Ok(s) =
//!   authorize(&req) { .. }`. The request goes on without a caller, so the
//!   helper authenticates optionally;
//! - the helper makes the check only when an argument is given (`if let
//!   Some(origin) = origin { check_member(origin)? }`) and the caller passes
//!   `None` or `false` there.

use syn::{
    Expr, ExprCall, ExprIf, ExprMatch, ExprMethodCall, Pat,
    visit::{self, Visit},
};

use super::{
    evidence::receiver_path,
    routes::{HandlerTarget, handler_target},
};

/// One call in a body, with what its site says about reach.
#[derive(Debug, Clone)]
pub(crate) struct CallShape {
    pub(crate) target: HandlerTarget,
    /// Argument positions that are literally `None` or `false` (a method
    /// call's receiver is position 0).
    pub(crate) absent: Vec<usize>,
    /// The call is made only when this parameter of the calling function
    /// is given (`Some(..)` or `true`).
    pub(crate) condition: Option<usize>,
    /// The caller discards the call's failure.
    pub(crate) swallowed: bool,
}

/// What a body says about reach: its calls, and the line ranges that run
/// only when a parameter is given.
#[derive(Debug, Clone, Default)]
pub(crate) struct Reach {
    pub(crate) shapes: Vec<CallShape>,
    /// `(first line, last line, parameter position)`.
    pub(crate) regions: Vec<(usize, usize, usize)>,
}

impl Reach {
    /// The parameter a line of the body depends on, if any.
    pub(crate) fn condition_at(&self, line: usize) -> Option<usize> {
        self.regions
            .iter()
            .find(|(first, last, _)| *first <= line && line <= *last)
            .map(|(_, _, parameter)| *parameter)
    }
}

pub(crate) fn reach(item: &syn::ItemFn) -> Reach {
    let parameters: Vec<Option<String>> = item
        .sig
        .inputs
        .iter()
        .map(|input| match input {
            syn::FnArg::Typed(typed) => match &*typed.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect();
    let mut visitor = ReachVisitor {
        parameters,
        conditions: Vec::new(),
        found: Reach::default(),
        statements: std::collections::HashSet::new(),
    };
    visitor.visit_block(&item.block);
    visitor.found
}

struct ReachVisitor {
    parameters: Vec<Option<String>>,
    conditions: Vec<usize>,
    found: Reach,
    /// Where the `if` expressions in statement position start: their
    /// value is not the function's, so the code after them runs whichever
    /// branch was taken.
    statements: std::collections::HashSet<(usize, usize)>,
}

/// Whether a block or branch leaves the function or rejects. `continue`
/// and `break` skip one item of a loop; the function goes on.
fn leaves(expr: &Expr) -> bool {
    struct Leaves(bool);
    impl<'ast> Visit<'ast> for Leaves {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = true;
        }
        fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) {
            self.0 = true;
        }
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if !logs(node) {
                self.0 = true;
            }
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut found = Leaves(false);
    found.visit_expr(expr);
    found.0 || super::evidence::expr_rejects(expr)
}

fn block_leaves(block: &syn::Block) -> bool {
    block.stmts.iter().any(|statement| match statement {
        syn::Stmt::Expr(expr, _) => leaves(expr),
        syn::Stmt::Local(local) => local.init.as_ref().is_some_and(|init| {
            leaves(&init.expr) || init.diverge.is_some()
        }),
        syn::Stmt::Macro(found) => !logs(&found.mac),
        _ => false,
    })
}

const PROBES: [&str; 4] = ["is_ok", "is_err", "is_some", "is_none"];

/// A value that stands in for a failure without rejecting anything:
/// `None`, `false`, `()`, a literal, `Default::default()`, an empty
/// collection, or a block that only logs before one of those.
pub(crate) fn neutral(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path
            .path
            .get_ident()
            .is_some_and(|ident| ident == "None" || ident == "false" || ident == "true"),
        Expr::Lit(_) => true,
        Expr::Tuple(tuple) => tuple.elems.is_empty(),
        Expr::Paren(inner) => neutral(&inner.expr),
        Expr::Block(block) => neutral_block(&block.block),
        Expr::Macro(found) => logs(&found.mac),
        Expr::Call(call) => {
            let Expr::Path(path) = &*call.func else {
                return false;
            };
            call.args.is_empty()
                && path.path.segments.last().is_some_and(|segment| {
                    segment.ident == "default" || segment.ident == "new"
                })
        }
        _ => false,
    }
}

fn neutral_block(block: &syn::Block) -> bool {
    block.stmts.iter().all(|statement| match statement {
        syn::Stmt::Expr(expr, _) => neutral(expr),
        syn::Stmt::Macro(found) => logs(&found.mac),
        _ => false,
    })
}

fn logs(mac: &syn::Macro) -> bool {
    mac.path.segments.last().is_some_and(|segment| {
        ["debug", "info", "warn", "error", "trace", "println", "eprintln"]
            .iter()
            .any(|name| segment.ident == name)
    })
}

fn names(pattern: &Pat, wanted: &[&str]) -> bool {
    match pattern {
        Pat::TupleStruct(tuple) => tuple
            .path
            .segments
            .last()
            .is_some_and(|segment| wanted.iter().any(|name| segment.ident == name)),
        Pat::Ident(ident) => ident.subpat.is_none() && wanted.iter().any(|name| ident.ident == name),
        Pat::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| wanted.iter().any(|name| segment.ident == name)),
        Pat::Paren(inner) => names(&inner.pat, wanted),
        Pat::Reference(inner) => names(&inner.pat, wanted),
        _ => false,
    }
}

/// `match call { Ok(v) => .., Err(_) => None }`: an arm for success, and
/// the failure arm yields a neutral value.
pub(crate) fn swallows_match(node: &ExprMatch) -> bool {
    if !super::rc::enabled("SWALLOWED") {
        return false;
    }
    let success = node.arms.iter().any(|arm| names(&arm.pat, &["Ok", "Some"]));
    let failure: Vec<&syn::Arm> = node
        .arms
        .iter()
        .filter(|arm| names(&arm.pat, &["Err", "None"]) || matches!(arm.pat, Pat::Wild(_)))
        .collect();
    success && !failure.is_empty() && failure.iter().all(|arm| neutral(&arm.body))
}

/// `if let Ok(v) = call { .. }` with no `else`, or a neutral one, whose
/// success branch does not return: the code after it runs either way.
pub(crate) fn swallows_if(node: &ExprIf) -> bool {
    if !super::rc::enabled("SWALLOWED") {
        return false;
    }
    let Expr::Let(binding) = &*node.cond else {
        return false;
    };
    if !names(&binding.pat, &["Ok", "Some"]) {
        return false;
    }
    let otherwise = match &node.else_branch {
        None => true,
        Some((_, branch)) => neutral(branch),
    };
    otherwise && !returns(&node.then_branch)
}

fn returns(block: &syn::Block) -> bool {
    struct Returns(bool);
    impl<'ast> Visit<'ast> for Returns {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.0 = true;
        }
        fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}
    }
    let mut found = Returns(false);
    found.visit_block(block);
    found.0
}

/// `.ok()`, `.unwrap_or_default()`, `.unwrap_or(None)`: the receiver's
/// failure becomes a neutral value.
pub(crate) fn swallows_method(node: &ExprMethodCall) -> bool {
    if !super::rc::enabled("SWALLOWED") {
        return false;
    }
    let method = node.method.to_string();
    match method.as_str() {
        "ok" | "unwrap_or_default" => node.args.is_empty(),
        "unwrap_or" => node.args.first().is_some_and(neutral),
        "unwrap_or_else" => matches!(node.args.first(), Some(Expr::Closure(closure)) if neutral(&closure.body)),
        _ => false,
    }
}

/// The parameter an expression tests for being given: `origin`,
/// `&origin`, `origin.as_ref()`, `origin.is_some()`.
fn tested(parameters: &[Option<String>], expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Path(path) => {
            let ident = path.path.get_ident()?.to_string();
            parameters.iter().position(|name| name.as_deref() == Some(ident.as_str()))
        }
        Expr::Reference(inner) => tested(parameters, &inner.expr),
        Expr::Paren(inner) => tested(parameters, &inner.expr),
        Expr::MethodCall(call)
            if call.args.is_empty()
                && ["as_ref", "as_deref", "clone", "is_some", "as_mut", "take", "cloned", "copied"]
                    .iter()
                    .any(|name| call.method == name) =>
        {
            tested(parameters, &call.receiver)
        }
        _ => None,
    }
}

fn lines(node: &impl syn::spanned::Spanned) -> (usize, usize) {
    let span = node.span();
    (span.start().line, span.end().line)
}

impl ReachVisitor {
    fn record(&mut self, target: HandlerTarget, arguments: Vec<&Expr>, swallowed: bool) {
        let absent = arguments
            .iter()
            .enumerate()
            .filter(|(_, argument)| {
                matches!(argument, Expr::Path(path) if path.path.is_ident("None") || path.path.is_ident("false"))
            })
            .map(|(position, _)| position)
            .collect();
        self.found.shapes.push(CallShape {
            target,
            absent,
            condition: self.conditions.last().copied(),
            swallowed,
        });
    }

    /// Visits an expression whose failure the caller discards: the calls
    /// that produce its value are marked, their arguments are not.
    fn swallowed(&mut self, expr: &Expr) {
        match expr {
            Expr::Await(inner) => self.swallowed(&inner.base),
            Expr::Paren(inner) => self.swallowed(&inner.expr),
            Expr::Reference(inner) => self.swallowed(&inner.expr),
            Expr::Call(call) => {
                if let Some(target @ HandlerTarget::Path { .. }) = handler_target(&call.func) {
                    self.record(target, call.args.iter().collect(), true);
                }
                for argument in &call.args {
                    self.visit_expr(argument);
                }
            }
            Expr::MethodCall(call) => {
                if let Some(receiver) = receiver_path(&call.receiver) {
                    self.record(
                        HandlerTarget::Method {
                            receiver,
                            method: call.method.to_string(),
                        },
                        std::iter::once(&*call.receiver).chain(call.args.iter()).collect(),
                        true,
                    );
                }
                self.swallowed(&call.receiver);
                for argument in &call.args {
                    self.visit_expr(argument);
                }
            }
            other => self.visit_expr(other),
        }
    }

    fn within(&mut self, parameter: usize, node: &impl syn::spanned::Spanned, visit: impl FnOnce(&mut Self)) {
        let (first, last) = lines(node);
        self.found.regions.push((first, last, parameter));
        self.conditions.push(parameter);
        visit(self);
        self.conditions.pop();
    }
}

impl ReachVisitor {
    /// Visits the condition of an `if` in statement position that never
    /// leaves the function: a call it only probes (`authorize(&req)
    /// .is_ok()`) decides what the code does next, not whether the
    /// request goes on.
    fn probed(&mut self, expr: &Expr) {
        match expr {
            Expr::Unary(inner) => self.probed(&inner.expr),
            Expr::Paren(inner) => self.probed(&inner.expr),
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) => {
                self.probed(&binary.left);
                self.probed(&binary.right);
            }
            Expr::MethodCall(call)
                if call.args.is_empty() && PROBES.iter().any(|probe| call.method == probe) =>
            {
                self.swallowed(&call.receiver);
            }
            other => self.visit_expr(other),
        }
    }
}

impl<'ast> Visit<'ast> for ReachVisitor {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let count = node.stmts.len();
        for (position, statement) in node.stmts.iter().enumerate() {
            if let syn::Stmt::Expr(Expr::If(branch), semicolon) = statement
                && (semicolon.is_some() || position + 1 < count)
            {
                let start = syn::spanned::Spanned::span(branch).start();
                self.statements.insert((start.line, start.column));
            }
        }
        visit::visit_block(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let start = syn::spanned::Spanned::span(node).start();
        if super::rc::enabled("SWALLOWED")
            && self.statements.contains(&(start.line, start.column))
            && !matches!(&*node.cond, Expr::Let(_))
            && !block_leaves(&node.then_branch)
            && !node.else_branch.as_ref().is_some_and(|(_, branch)| leaves(branch))
        {
            self.probed(&node.cond);
            self.visit_block(&node.then_branch);
            if let Some((_, branch)) = &node.else_branch {
                self.visit_expr(branch);
            }
            return;
        }
        // `if let Some(origin) = origin { .. }`, `if strict { .. }`.
        let parameter = match &*node.cond {
            Expr::Let(binding) if names(&binding.pat, &["Some"]) => tested(&self.parameters, &binding.expr),
            other => tested(&self.parameters, other),
        };
        if swallows_if(node)
            && let Expr::Let(binding) = &*node.cond
        {
            self.swallowed(&binding.expr);
        } else {
            self.visit_expr(&node.cond);
        }
        match parameter {
            Some(parameter) if super::rc::enabled("CONDITIONAL") => {
                self.within(parameter, &node.then_branch, |visitor| visitor.visit_block(&node.then_branch));
            }
            _ => self.visit_block(&node.then_branch),
        }
        if let Some((_, branch)) = &node.else_branch {
            self.visit_expr(branch);
        }
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        if swallows_match(node) {
            self.swallowed(&node.expr);
        } else {
            self.visit_expr(&node.expr);
        }
        let parameter = tested(&self.parameters, &node.expr).filter(|_| super::rc::enabled("CONDITIONAL"));
        for arm in &node.arms {
            if let Pat::Guard(guarded) = &arm.pat {
                self.visit_expr(&guarded.guard);
            }
            match parameter {
                Some(parameter) if names(&arm.pat, &["Some", "true"]) => {
                    self.within(parameter, &arm.body, |visitor| visitor.visit_expr(&arm.body));
                }
                _ => self.visit_expr(&arm.body),
            }
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Some(target @ HandlerTarget::Path { .. }) = handler_target(&node.func) {
            self.record(target, node.args.iter().collect(), false);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if let Some(receiver) = receiver_path(&node.receiver) {
            self.record(
                HandlerTarget::Method {
                    receiver,
                    method: node.method.to_string(),
                },
                std::iter::once(&*node.receiver).chain(node.args.iter()).collect(),
                false,
            );
        }
        if swallows_method(node) {
            self.swallowed(&node.receiver);
        } else {
            self.visit_expr(&node.receiver);
        }
        for argument in &node.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        // A closure runs when its caller decides; nothing outside it
        // makes it conditional or swallowed.
        let conditions = std::mem::take(&mut self.conditions);
        visit::visit_expr_closure(self, node);
        self.conditions = conditions;
    }

    fn visit_item_fn(&mut self, _: &'ast syn::ItemFn) {}
    fn visit_item_impl(&mut self, _: &'ast syn::ItemImpl) {}
}
