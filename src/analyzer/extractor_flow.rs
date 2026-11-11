//! What an extractor checks beyond its own `from_request` body.
//!
//! ```rust,ignore
//! impl FromRequest for OwnedRequest {
//!     fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
//!         let req = req.clone();
//!         Box::pin(async move {
//!             let caller = TokenCaller::from_request(&req, &mut Payload::None).await?;
//!             Ok(OwnedRequest { caller })
//!         })
//!     }
//! }
//! impl FromRequest for TokenCaller {
//!     fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
//!         ready(Self::read(req.headers().get("authorization"), req.uri()))
//!     }
//! }
//! impl TokenCaller {
//!     fn read(header: Option<&HeaderValue>, uri: &Uri) -> Result<Self, Error> {
//!         let token = decode(header.ok_or(Error::Missing)?)?;
//!         if token.account != account_in(uri)? {
//!             return Err(Error::Mismatch);
//!         }
//!         Ok(Self(token))
//!     }
//! }
//! ```
//!
//! `OwnedRequest` rejects whatever `TokenCaller` rejects, and `TokenCaller`
//! rejects a caller whose credential does not match the request path: an
//! ownership check, two calls away from the handler's argument list.
//!
//! Two things are followed from a `from_request` body, to a fixed depth:
//! the extractors it runs (`X::from_request`, `X::extract`,
//! `<(A, B)>::from_request`), unless it discards their failure (`.ok()`),
//! and the functions of the scanned code it calls. Along the way values
//! are marked by where they come from: a credential (request headers,
//! cookies, a session, what another caller extractor returned) or the
//! request path. A comparison of a credential value with a path value, in
//! a branch that rejects, is the ownership check. Nothing is read from the
//! names of the functions or values involved.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use syn::{
    Block, Expr, FnArg, GenericArgument, ImplItem, Item, Pat, PathArguments, Stmt, Type,
    punctuated::Punctuated,
    spanned::Spanned,
    visit::{self, Visit},
};

use super::{
    extractors::{Learned, Via, classify, names_caller},
    model::{AuthEvidenceKind, EvidenceTier},
};

/// The value comes from a credential the request presents.
const CRED: u8 = 1;
/// The value comes from the request path.
const PATH: u8 = 2;

/// Calls followed from a `from_request` body, and extractors nested.
const MAX_DEPTH: usize = 5;

/// Request methods that read a credential.
const CREDENTIAL_METHODS: [&str; 5] = ["headers", "cookie", "cookies", "get_session", "get_identity"];
/// Request methods that read the path.
const PATH_METHODS: [&str; 4] = ["uri", "path", "match_info", "match_pattern"];
/// Methods that discard a failure: an extractor run through one of these
/// does not reject the request.
const DISCARDING_METHODS: [&str; 8] = [
    "ok",
    "unwrap_or",
    "unwrap_or_default",
    "unwrap_or_else",
    "is_ok",
    "is_err",
    "or",
    "or_else",
];

/// Whether the nested-extractor round is on: `ARCHER_P11=0` turns it off.
pub(crate) fn enabled() -> bool {
    std::env::var("ARCHER_P11").map_or(true, |value| value != "0")
}

type FnKey = (Option<String>, String);

struct FnDef<'a> {
    file: &'a Path,
    owner: Option<String>,
    /// Parameter names by position; a receiver is `self`.
    inputs: Vec<Option<String>>,
    block: &'a Block,
}

struct ExtractorDef<'a> {
    file: &'a Path,
    body: &'a Block,
}

/// The extractors and functions of the scanned code, by name.
#[derive(Default)]
pub(crate) struct Index<'a> {
    /// `None`: several functions share the key, so a call is not followed.
    fns: HashMap<FnKey, Option<FnDef<'a>>>,
    extractors: HashMap<String, Vec<ExtractorDef<'a>>>,
}

impl<'a> Index<'a> {
    pub(crate) fn build(files: impl IntoIterator<Item = (&'a Path, &'a syn::File)>) -> Self {
        let mut index = Self::default();
        for (path, file) in files {
            index.collect(&file.items, path, false);
        }
        index
    }

    pub(crate) fn extractor_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.extractors.keys().cloned().collect();
        names.sort();
        names
    }

    fn add_fn(&mut self, key: FnKey, def: FnDef<'a>) {
        match self.fns.get(&key) {
            None => {
                self.fns.insert(key, Some(def));
            }
            Some(_) => {
                self.fns.insert(key, None);
            }
        }
    }

    fn collect(&mut self, items: &'a [Item], file: &'a Path, in_test: bool) {
        for item in items {
            match item {
                Item::Mod(module) => {
                    if let Some((_, items)) = &module.content {
                        let test = in_test || module.attrs.iter().any(is_cfg_test);
                        self.collect(items, file, test);
                    }
                }
                Item::Fn(function) if !in_test => {
                    self.add_fn(
                        (None, function.sig.ident.to_string()),
                        FnDef {
                            file,
                            owner: None,
                            inputs: inputs(&function.sig),
                            block: &function.block,
                        },
                    );
                }
                Item::Impl(implementation) => {
                    let Type::Path(self_type) = &*implementation.self_ty else {
                        continue;
                    };
                    let Some(name) = self_type.path.segments.last().map(|s| s.ident.to_string())
                    else {
                        continue;
                    };
                    let from_request = implementation.trait_.as_ref().is_some_and(|(path, _)| {
                        path.segments
                            .last()
                            .is_some_and(|segment| segment.ident == "FromRequest")
                    });
                    for item in &implementation.items {
                        let ImplItem::Fn(function) = item else {
                            continue;
                        };
                        if from_request && function.sig.ident == "from_request" {
                            self.extractors.entry(name.clone()).or_default().push(ExtractorDef {
                                file,
                                body: &function.block,
                            });
                        } else if !in_test {
                            self.add_fn(
                                (Some(name.clone()), function.sig.ident.to_string()),
                                FnDef {
                                    file,
                                    owner: Some(name.clone()),
                                    inputs: inputs(&function.sig),
                                    block: &function.block,
                                },
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

fn is_cfg_test(attribute: &syn::Attribute) -> bool {
    attribute.path().is_ident("cfg")
        && attribute
            .meta
            .require_list()
            .is_ok_and(|list| list.tokens.to_string().split(|c: char| !c.is_alphanumeric()).any(|word| word == "test"))
}

fn inputs(signature: &syn::Signature) -> Vec<Option<String>> {
    signature
        .inputs
        .iter()
        .map(|input| match input {
            FnArg::Receiver(_) => Some("self".to_string()),
            FnArg::Typed(typed) => match &*typed.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => None,
            },
        })
        .collect()
}

/// What following one `from_request` body found.
#[derive(Default)]
struct Outcome {
    /// Rejecting comparisons of a credential value with a path value.
    sites: Vec<(PathBuf, usize)>,
    /// Extractors it runs and whose failure it keeps.
    inner: Vec<String>,
}

struct Scope<'a> {
    file: &'a Path,
    owner: Option<String>,
    marks: HashMap<String, u8>,
    /// Every mark read in the function.
    seen: u8,
}

pub(crate) struct Resolver<'i, 'a> {
    index: &'i Index<'a>,
    done: HashMap<String, Option<Learned>>,
    resolving: Vec<String>,
    following: Vec<FnKey>,
    /// Inside the receiver of a method that discards a failure.
    discarding: usize,
}

enum Callee {
    /// Extractor types run, each with whether its failure can be kept.
    Extractors(Vec<(String, bool)>),
    Local(FnKey),
    Other,
}

impl<'i, 'a> Resolver<'i, 'a> {
    pub(crate) fn new(index: &'i Index<'a>) -> Self {
        Self {
            index,
            done: HashMap::new(),
            resolving: Vec::new(),
            following: Vec::new(),
            discarding: 0,
        }
    }

    /// What the extractor type checks. `None`: it checks nothing found, or
    /// several impls of that name disagree.
    pub(crate) fn resolve(&mut self, name: &str) -> Option<Learned> {
        if let Some(done) = self.done.get(name) {
            return done.clone();
        }
        if self.resolving.len() >= MAX_DEPTH || self.resolving.iter().any(|open| open == name) {
            return None;
        }
        let index = self.index;
        let defs = index.extractors.get(name)?;
        self.resolving.push(name.to_string());
        let mut result: Option<Option<Learned>> = None;
        for def in defs {
            let Some(found) = self.resolve_one(name, def) else {
                continue;
            };
            match &result {
                None => result = Some(Some(found)),
                Some(Some(previous)) if *previous != found => result = Some(None),
                _ => {}
            }
        }
        self.resolving.pop();
        let result = result.flatten();
        // A result cut short by a cycle is not kept for the types still open.
        if self.resolving.is_empty() {
            self.done.insert(name.to_string(), result.clone());
        }
        result
    }

    fn resolve_one(&mut self, name: &str, def: &'i ExtractorDef<'a>) -> Option<Learned> {
        let own = classify(def.body);
        if !enabled() {
            return own;
        }
        let saved_following = std::mem::take(&mut self.following);
        let saved_discarding = std::mem::take(&mut self.discarding);
        let mut outcome = Outcome::default();
        let mut scope = Scope {
            file: def.file,
            owner: Some(name.to_string()),
            marks: HashMap::new(),
            seen: 0,
        };
        self.walk_block(def.body, &mut scope, &mut outcome);
        self.following = saved_following;
        self.discarding = saved_discarding;

        let tier = |learned: &Option<Learned>| {
            learned
                .as_ref()
                .map_or(EvidenceTier::None, |learned| EvidenceTier::of(&learned.kind))
        };
        let mut best = own;
        let mut credential = scope.seen & CRED != 0;
        if let Some((file, line)) = outcome.sites.first()
            && tier(&best) < EvidenceTier::Resource
        {
            best = Some(Learned {
                kind: AuthEvidenceKind::OwnershipCheck,
                requirements: Vec::new(),
                via: Some(Via {
                    extractor: name.to_string(),
                    chain: vec![name.to_string()],
                    site: Some((file.clone(), *line)),
                }),
                credential: true,
                name_based: false,
            });
        }
        for inner in &outcome.inner {
            let Some(found) = self.resolve(inner) else {
                continue;
            };
            credential |= found.credential;
            if EvidenceTier::of(&found.kind) > tier(&best) {
                let (extractor, mut chain, site) = match &found.via {
                    Some(via) => (via.extractor.clone(), via.chain.clone(), via.site.clone()),
                    None => (inner.clone(), vec![inner.clone()], None),
                };
                chain.insert(0, name.to_string());
                best = Some(Learned {
                    kind: found.kind,
                    requirements: found.requirements,
                    via: Some(Via { extractor, chain, site }),
                    credential: found.credential,
                    name_based: found.name_based,
                });
            }
        }
        // P8: an extractor that fails without a credential, or that takes a
        // value a credential reader stored, identifies the caller whatever
        // its words say.
        if super::structural::enabled() {
            let structural = super::structural::caller_extractor(name)
                || (super::structural::credential_extractor(name) && rejects_block(def.body));
            if best.is_none() && structural {
                best = Some(Learned {
                    kind: AuthEvidenceKind::IdentityExtraction,
                    requirements: Vec::new(),
                    via: None,
                    credential,
                    name_based: false,
                });
            } else if let Some(found) = &mut best
                && found.kind == AuthEvidenceKind::IdentityExtraction
                && structural
            {
                found.name_based = false;
            }
        }
        if let Some(best) = &mut best {
            best.credential |= credential;
        }
        best
    }

    fn walk_block(&mut self, block: &'i Block, scope: &mut Scope<'a>, outcome: &mut Outcome) {
        for statement in &block.stmts {
            match statement {
                Stmt::Local(local) => {
                    if let Some(init) = &local.init {
                        let marks = self.marks(&init.expr, scope, outcome);
                        self.walk_nested(&init.expr, scope, outcome);
                        bind(&local.pat, marks, scope);
                        if let Some((_, diverge)) = &init.diverge {
                            self.walk_expr(diverge, scope, outcome);
                        }
                    }
                }
                Stmt::Expr(expr, _) => self.walk_expr(expr, scope, outcome),
                Stmt::Macro(statement) => {
                    for argument in macro_arguments(&statement.mac) {
                        scope.seen |= ident_marks(&argument, scope);
                    }
                }
                Stmt::Item(_) => {}
            }
        }
    }

    fn walk_expr(&mut self, expr: &'i Expr, scope: &mut Scope<'a>, outcome: &mut Outcome) {
        match expr {
            Expr::If(branch) => {
                let rejects = rejects_block(&branch.then_branch)
                    || branch.else_branch.as_ref().is_some_and(|(_, other)| rejects_expr(other));
                self.condition(&branch.cond, rejects, scope, outcome);
                self.walk_block(&branch.then_branch, scope, outcome);
                if let Some((_, other)) = &branch.else_branch {
                    self.walk_expr(other, scope, outcome);
                }
            }
            Expr::Match(matched) => {
                let marks = self.marks(&matched.expr, scope, outcome);
                self.walk_nested(&matched.expr, scope, outcome);
                let rejects = matched.arms.iter().any(|arm| rejects_expr(&arm.body));
                for arm in &matched.arms {
                    bind(&arm.pat, marks, scope);
                    if let Pat::Guard(guarded) = &arm.pat {
                        self.condition(&guarded.guard, rejects, scope, outcome);
                    }
                    self.walk_expr(&arm.body, scope, outcome);
                }
            }
            Expr::Block(block) => self.walk_block(&block.block, scope, outcome),
            Expr::Async(block) => self.walk_block(&block.block, scope, outcome),
            Expr::Unsafe(block) => self.walk_block(&block.block, scope, outcome),
            Expr::Loop(looped) => self.walk_block(&looped.body, scope, outcome),
            Expr::While(looped) => {
                self.condition(&looped.cond, false, scope, outcome);
                self.walk_block(&looped.body, scope, outcome);
            }
            Expr::ForLoop(looped) => {
                let marks = self.marks(&looped.expr, scope, outcome);
                self.walk_nested(&looped.expr, scope, outcome);
                bind(&looped.pat, marks, scope);
                self.walk_block(&looped.body, scope, outcome);
            }
            Expr::Closure(closure) => self.walk_expr(&closure.body, scope, outcome),
            Expr::Assign(assign) => {
                let marks = self.marks(&assign.right, scope, outcome);
                self.walk_nested(&assign.right, scope, outcome);
                if let Expr::Path(path) = &*assign.left
                    && let Some(ident) = path.path.get_ident()
                {
                    scope.marks.insert(ident.to_string(), marks);
                }
            }
            Expr::Let(bound) => {
                let marks = self.marks(&bound.expr, scope, outcome);
                bind(&bound.pat, marks, scope);
            }
            Expr::Return(returned) => {
                if let Some(value) = &returned.expr {
                    self.walk_expr(value, scope, outcome);
                }
            }
            Expr::Paren(inner) => self.walk_expr(&inner.expr, scope, outcome),
            _ => {
                self.marks(expr, scope, outcome);
                self.walk_nested(expr, scope, outcome);
            }
        }
    }

    /// Walks the branches, blocks and closures inside an expression.
    fn walk_nested(&mut self, expr: &'i Expr, scope: &mut Scope<'a>, outcome: &mut Outcome) {
        let mut nested = Nested::default();
        nested.visit_expr(expr);
        for inner in nested.found {
            self.walk_expr(inner, scope, outcome);
        }
    }

    /// A branch condition: binds what it matches, and records a comparison
    /// of a credential value with a path value when a branch rejects.
    fn condition(&mut self, condition: &'i Expr, rejects: bool, scope: &mut Scope<'a>, outcome: &mut Outcome) {
        let mut parts = ConditionParts::default();
        parts.visit_expr(condition);
        for bound in parts.lets {
            let marks = self.marks(&bound.expr, scope, outcome);
            bind(&bound.pat, marks, scope);
        }
        for comparison in parts.comparisons {
            let left = self.marks(&comparison.left, scope, outcome);
            let right = self.marks(&comparison.right, scope, outcome);
            let held = |credential: u8, path: u8| credential & CRED != 0 && path & PATH != 0 && path & CRED == 0;
            if rejects && (held(left, right) || held(right, left)) {
                let site = (scope.file.to_path_buf(), comparison.op.span().start().line);
                if !outcome.sites.contains(&site) {
                    outcome.sites.push(site);
                }
            }
        }
        self.marks(condition, scope, outcome);
        self.walk_nested(condition, scope, outcome);
    }

    /// Where the value of an expression comes from.
    fn marks(&mut self, expr: &'i Expr, scope: &mut Scope<'a>, outcome: &mut Outcome) -> u8 {
        let marks = match expr {
            Expr::Path(path) => path
                .path
                .get_ident()
                .and_then(|ident| scope.marks.get(&ident.to_string()).copied())
                .unwrap_or(0),
            Expr::Field(field) => self.marks(&field.base, scope, outcome),
            Expr::Reference(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Paren(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Group(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Unary(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Try(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Await(inner) => self.marks(&inner.base, scope, outcome),
            Expr::Cast(inner) => self.marks(&inner.expr, scope, outcome),
            Expr::Index(index) => {
                self.marks(&index.expr, scope, outcome) | self.marks(&index.index, scope, outcome)
            }
            Expr::Binary(binary) => {
                self.marks(&binary.left, scope, outcome) | self.marks(&binary.right, scope, outcome)
            }
            Expr::Tuple(tuple) => {
                let mut marks = 0;
                for element in &tuple.elems {
                    marks |= self.marks(element, scope, outcome);
                }
                marks
            }
            Expr::Struct(built) => {
                let mut marks = 0;
                for field in &built.fields {
                    marks |= self.marks(&field.expr, scope, outcome);
                }
                marks
            }
            Expr::MethodCall(call) => {
                let name = call.method.to_string();
                let discards = DISCARDING_METHODS.contains(&name.as_str());
                if discards {
                    self.discarding += 1;
                }
                let mut marks = self.marks(&call.receiver, scope, outcome);
                if discards {
                    self.discarding -= 1;
                }
                for argument in &call.args {
                    marks |= self.marks(argument, scope, outcome);
                }
                marks | method_source(call)
            }
            Expr::Call(call) => {
                let mut arguments = Vec::new();
                let mut marks = 0;
                for argument in &call.args {
                    let found = self.marks(argument, scope, outcome);
                    arguments.push(found);
                    marks |= found;
                }
                match self.callee(&call.func, scope) {
                    Callee::Extractors(types) => {
                        for (ty, keeps_failure) in types {
                            if ty == "Path" {
                                marks |= PATH;
                            } else if self.index.extractors.contains_key(&ty) {
                                if self.resolve(&ty).is_some() {
                                    marks |= CRED;
                                }
                                if keeps_failure && self.discarding == 0 && !outcome.inner.contains(&ty) {
                                    outcome.inner.push(ty);
                                }
                            } else if super::structural::caller_type(&ty) || names_caller(&ty) {
                                marks |= CRED;
                            }
                        }
                    }
                    Callee::Local(key) => marks |= self.follow(&key, &arguments, outcome),
                    Callee::Other => {}
                }
                marks
            }
            Expr::Macro(invoked) => {
                let mut marks = 0;
                for argument in macro_arguments(&invoked.mac) {
                    marks |= ident_marks(&argument, scope);
                }
                marks
            }
            other => ident_marks(other, scope),
        };
        scope.seen |= marks;
        marks
    }

    fn callee(&self, func: &Expr, scope: &Scope<'a>) -> Callee {
        let Expr::Path(path) = func else {
            return Callee::Other;
        };
        let segments: Vec<&syn::PathSegment> = path.path.segments.iter().collect();
        let Some(last) = segments.last().map(|segment| segment.ident.to_string()) else {
            return Callee::Other;
        };
        let owner = (segments.len() >= 2).then(|| segments[segments.len() - 2]).and_then(|segment| {
            let name = segment.ident.to_string();
            if name == "Self" {
                scope.owner.clone()
            } else {
                name.starts_with(|c: char| c.is_ascii_uppercase()).then_some(name)
            }
        });
        let key: FnKey = (owner.clone(), last.clone());
        if matches!(self.index.fns.get(&key), Some(Some(_))) && path.qself.is_none() {
            return Callee::Local(key);
        }
        if last == "from_request" || last == "extract" {
            let mut types = Vec::new();
            if let Some(qself) = &path.qself {
                type_names(&qself.ty, true, &mut types);
            } else if segments.len() >= 2 {
                let segment = segments[segments.len() - 2];
                if segment.ident == "Option" {
                    arguments_names(&segment.arguments, false, &mut types);
                } else if let Some(owner) = owner {
                    types.push((owner, true));
                }
            }
            if !types.is_empty() {
                return Callee::Extractors(types);
            }
        }
        Callee::Other
    }

    /// Follows a call into a function of the scanned code. What it returns
    /// is taken to come from its arguments and from what it reads.
    fn follow(&mut self, key: &FnKey, arguments: &[u8], outcome: &mut Outcome) -> u8 {
        let passed = arguments.iter().fold(0, |all, marks| all | marks);
        if self.following.len() >= MAX_DEPTH || self.following.contains(key) {
            return passed;
        }
        let index = self.index;
        let Some(Some(def)) = index.fns.get(key) else {
            return passed;
        };
        let mut scope = Scope {
            file: def.file,
            owner: def.owner.clone(),
            marks: HashMap::new(),
            seen: 0,
        };
        for (name, marks) in def.inputs.iter().zip(arguments) {
            if let Some(name) = name {
                scope.marks.insert(name.clone(), *marks);
            }
        }
        self.following.push(key.clone());
        let discarding = std::mem::take(&mut self.discarding);
        self.walk_block(def.block, &mut scope, outcome);
        self.discarding = discarding;
        self.following.pop();
        passed | scope.seen
    }
}

fn method_source(call: &syn::ExprMethodCall) -> u8 {
    let name = call.method.to_string();
    if CREDENTIAL_METHODS.contains(&name.as_str()) {
        return CRED;
    }
    if PATH_METHODS.contains(&name.as_str()) {
        return PATH;
    }
    // `req.extensions().get::<Claims>()`: what authentication stored.
    if (name == "get" || (name == "remove" && super::structural::enabled()))
        && let Some(turbofish) = &call.turbofish
    {
        let mut types = Vec::new();
        for argument in &turbofish.args {
            if let GenericArgument::Type(ty) = argument {
                type_names(ty, true, &mut types);
            }
        }
        if types.iter().any(|(ty, _)| super::structural::caller_type(ty) || names_caller(ty)) {
            return CRED;
        }
    }
    0
}

/// The type names an extractor call runs: `(A, Option<B>)` runs `A`, and
/// `B` without keeping its failure.
fn type_names(ty: &Type, keeps_failure: bool, names: &mut Vec<(String, bool)>) {
    match ty {
        Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return;
            };
            if segment.ident == "Option" {
                arguments_names(&segment.arguments, false, names);
            } else {
                names.push((segment.ident.to_string(), keeps_failure));
            }
        }
        Type::Tuple(tuple) => {
            for element in &tuple.elems {
                type_names(element, keeps_failure, names);
            }
        }
        Type::Paren(inner) => type_names(&inner.elem, keeps_failure, names),
        Type::Group(inner) => type_names(&inner.elem, keeps_failure, names),
        Type::Reference(inner) => type_names(&inner.elem, keeps_failure, names),
        _ => {}
    }
}

fn arguments_names(arguments: &PathArguments, keeps_failure: bool, names: &mut Vec<(String, bool)>) {
    if let PathArguments::AngleBracketed(arguments) = arguments {
        for argument in &arguments.args {
            if let GenericArgument::Type(ty) = argument {
                type_names(ty, keeps_failure, names);
            }
        }
    }
}

fn macro_arguments(invoked: &syn::Macro) -> Vec<Expr> {
    invoked
        .parse_body_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated)
        .map(|arguments| arguments.into_iter().collect())
        .unwrap_or_default()
}

fn bind(pattern: &Pat, marks: u8, scope: &mut Scope<'_>) {
    struct Names<'s, 'a> {
        marks: u8,
        scope: &'s mut Scope<'a>,
    }
    impl<'ast> Visit<'ast> for Names<'_, '_> {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            self.scope.marks.insert(node.ident.to_string(), self.marks);
            visit::visit_pat_ident(self, node);
        }
    }
    Names { marks, scope }.visit_pat(pattern);
}

/// The marks of every name and request read in an expression, without
/// following its calls.
fn ident_marks(expr: &Expr, scope: &Scope<'_>) -> u8 {
    struct Reads<'s, 'a> {
        scope: &'s Scope<'a>,
        marks: u8,
    }
    impl<'ast> Visit<'ast> for Reads<'_, '_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if let Some(ident) = node.path.get_ident()
                && let Some(marks) = self.scope.marks.get(&ident.to_string())
            {
                self.marks |= marks;
            }
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.marks |= method_source(node);
            visit::visit_expr_method_call(self, node);
        }
    }
    let mut reads = Reads { scope, marks: 0 };
    reads.visit_expr(expr);
    reads.marks
}

/// Branches, blocks and closures directly inside an expression.
#[derive(Default)]
struct Nested<'x> {
    found: Vec<&'x Expr>,
}

impl<'x> Visit<'x> for Nested<'x> {
    fn visit_expr(&mut self, node: &'x Expr) {
        match node {
            Expr::If(_)
            | Expr::Match(_)
            | Expr::Block(_)
            | Expr::Async(_)
            | Expr::Unsafe(_)
            | Expr::Loop(_)
            | Expr::While(_)
            | Expr::ForLoop(_)
            | Expr::Closure(_) => self.found.push(node),
            _ => visit::visit_expr(self, node),
        }
    }
}

/// The `let` bindings and equality comparisons of a condition.
#[derive(Default)]
struct ConditionParts<'x> {
    lets: Vec<&'x syn::ExprLet>,
    comparisons: Vec<&'x syn::ExprBinary>,
}

impl<'x> Visit<'x> for ConditionParts<'x> {
    fn visit_expr(&mut self, node: &'x Expr) {
        match node {
            Expr::Let(bound) => {
                self.lets.push(bound);
                visit::visit_expr(self, node);
            }
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) => {
                self.comparisons.push(binary);
            }
            Expr::Closure(_) | Expr::Block(_) | Expr::Async(_) | Expr::If(_) | Expr::Match(_) => {}
            _ => visit::visit_expr(self, node),
        }
    }
}

#[derive(Default)]
struct Rejects {
    found: bool,
}

impl<'ast> Visit<'ast> for Rejects {
    fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) {
        self.found = true;
    }
    fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
        self.found = true;
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && path
                .path
                .segments
                .last()
                .is_some_and(|last| last.ident == "Err" || last.ident == "err")
        {
            self.found = true;
        }
        visit::visit_expr_call(self, node);
    }
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.segments.last().is_some_and(|last| last.ident == "bail") {
            self.found = true;
        }
    }
}

fn rejects_block(block: &Block) -> bool {
    let mut rejects = Rejects::default();
    rejects.visit_block(block);
    rejects.found
}

fn rejects_expr(expr: &Expr) -> bool {
    let mut rejects = Rejects::default();
    rejects.visit_expr(expr);
    rejects.found
}
