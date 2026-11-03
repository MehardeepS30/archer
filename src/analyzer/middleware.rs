//! Middleware written in the scanned crate, evaluated rather than trusted by
//! name.
//!
//! A `.wrap(AuthService)` whose `Service::call` only checks the caller when
//! `req.path()` matches some pattern protects whichever routes match at
//! runtime, which static analysis cannot settle. Such a component is recorded
//! here so the routes it wraps are reported as unverified instead of
//! authenticated.

use std::{cell::RefCell, collections::HashSet};
use syn::{
    Block, Expr, FnArg, ImplItem, Item, ItemImpl, Type,
    visit::{self, Visit},
};

/// Request accessors whose value names the requested route.
const PATH_ACCESSORS: [&str; 6] = [
    "path",
    "uri",
    "match_info",
    "match_pattern",
    "match_name",
    "full_url",
];

thread_local! {
    /// Components of the crate under analysis whose checks depend on the
    /// request path. Set once per analysis, before routes are extracted, on
    /// the analysis thread.
    static PATH_CONDITIONAL: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

/// Records the path-conditional components of the files about to be analyzed.
pub(crate) fn index_path_conditional<'a>(files: impl IntoIterator<Item = &'a syn::File>) {
    let mut transforms: Vec<(String, String)> = Vec::new();
    let mut conditional: HashSet<String> = HashSet::new();
    for file in files {
        collect(&file.items, &mut transforms, &mut conditional);
    }
    // `impl Transform for AuthService { type Transform = AuthMiddleware<S>; }`
    // makes `AuthService` as conditional as the service it builds.
    let mut changed = true;
    while changed {
        changed = false;
        for (factory, service) in &transforms {
            if conditional.contains(service) && conditional.insert(factory.clone()) {
                changed = true;
            }
        }
    }
    PATH_CONDITIONAL.with(|set| *set.borrow_mut() = conditional);
}

/// The first component named in a `.wrap(..)` argument whose checks depend
/// on the request path: a crate-defined middleware type or function, or a
/// `wrap_fn` closure that branches on the path itself.
pub(crate) fn path_conditional_component(arg: &Expr) -> Option<String> {
    struct Names<'a> {
        set: &'a HashSet<String>,
        found: Option<String>,
    }
    impl<'ast> Visit<'ast> for Names<'_> {
        fn visit_path(&mut self, path: &'ast syn::Path) {
            if self.found.is_none() {
                if let Some(last) = path.segments.last() {
                    let name = last.ident.to_string();
                    if self.set.contains(&name) {
                        self.found = Some(name);
                    }
                }
            }
            visit::visit_path(self, path);
        }
        fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
            if self.found.is_none() && decides_by_path_expr(&closure.body) {
                self.found = Some("<closure>".into());
            }
            visit::visit_expr_closure(self, closure);
        }
    }
    PATH_CONDITIONAL.with(|set| {
        let set = set.borrow();
        let mut names = Names { set: &set, found: None };
        names.visit_expr(arg);
        names.found
    })
}

fn collect(items: &[Item], transforms: &mut Vec<(String, String)>, conditional: &mut HashSet<String>) {
    for item in items {
        match item {
            Item::Impl(item) => collect_impl(item, transforms, conditional),
            Item::Fn(function) => {
                // `from_fn(check)` / `HttpAuthentication::bearer(validator)`:
                // a free function that receives the request.
                if takes_service_request(&function.sig) && decides_by_path(&function.block) {
                    conditional.insert(function.sig.ident.to_string());
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(items, transforms, conditional);
                }
            }
            _ => {}
        }
    }
}

fn collect_impl(item: &ItemImpl, transforms: &mut Vec<(String, String)>, conditional: &mut HashSet<String>) {
    let Some((trait_path, _)) = &item.trait_ else {
        return;
    };
    let Some(trait_name) = trait_path.segments.last().map(|segment| segment.ident.to_string()) else {
        return;
    };
    let Some(self_name) = type_name(&item.self_ty) else {
        return;
    };
    match trait_name.as_str() {
        "Transform" => {
            for member in &item.items {
                if let ImplItem::Type(alias) = member {
                    if alias.ident == "Transform" {
                        if let Some(service) = type_name(&alias.ty) {
                            transforms.push((self_name.clone(), service));
                        }
                    }
                }
            }
        }
        "Service" => {
            for member in &item.items {
                if let ImplItem::Fn(function) = member {
                    if function.sig.ident == "call" && decides_by_path(&function.block) {
                        conditional.insert(self_name.clone());
                    }
                }
            }
        }
        _ => {}
    }
}

fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|segment| segment.ident.to_string()),
        Type::Reference(reference) => type_name(&reference.elem),
        Type::Paren(paren) => type_name(&paren.elem),
        _ => None,
    }
}

fn takes_service_request(signature: &syn::Signature) -> bool {
    signature.inputs.iter().any(|input| match input {
        FnArg::Typed(typed) => type_name(&typed.ty).is_some_and(|name| name == "ServiceRequest"),
        FnArg::Receiver(_) => false,
    })
}

/// Whether a body branches on the request path: an `if`, `match`, or match
/// guard whose condition reads `req.path()` or similar, directly or through
/// a binding initialized from it.
fn decides_by_path(block: &Block) -> bool {
    let mut visitor = PathBranches::default();
    visitor.visit_block(block);
    visitor.found
}

fn decides_by_path_expr(expr: &Expr) -> bool {
    let mut visitor = PathBranches::default();
    visitor.visit_expr(expr);
    visitor.found
}

#[derive(Default)]
struct PathBranches {
    bindings: HashSet<String>,
    found: bool,
}

impl PathBranches {
    fn reads_path(&self, expr: &Expr) -> bool {
        struct Reads<'a> {
            bindings: &'a HashSet<String>,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Reads<'_> {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                if PATH_ACCESSORS.iter().any(|name| call.method == name) {
                    self.found = true;
                }
                visit::visit_expr_method_call(self, call);
            }
            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                if path
                    .path
                    .get_ident()
                    .is_some_and(|ident| self.bindings.contains(&ident.to_string()))
                {
                    self.found = true;
                }
            }
        }
        let mut reads = Reads { bindings: &self.bindings, found: false };
        reads.visit_expr(expr);
        reads.found
    }
}

impl<'ast> Visit<'ast> for PathBranches {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            if self.reads_path(&init.expr) {
                let mut names = HashSet::new();
                super::routes::pattern_bindings(&local.pat, &mut names);
                self.bindings.extend(names);
            }
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.reads_path(&node.cond) {
            self.found = true;
        }
        visit::visit_expr_if(self, node);
    }
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.reads_path(&node.expr) {
            self.found = true;
        }
        visit::visit_expr_match(self, node);
    }
    fn visit_pat_guard(&mut self, node: &'ast syn::PatGuard) {
        if self.reads_path(&node.guard) {
            self.found = true;
        }
        visit::visit_pat_guard(self, node);
    }
    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        if self.reads_path(&node.cond) {
            self.found = true;
        }
        visit::visit_expr_while(self, node);
    }
}
