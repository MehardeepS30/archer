//! Declared route tables: an attribute on a type that lists its routes as
//! `"path" => method(handler)` entries, mounted with `.configure(<T as _>::configure)`.
//!
//! ```rust,ignore
//! #[routes(routes(
//!     "" => [post(create_key), get(list_keys)],
//!     "/{key}" => get(get_key),
//!     "/settings" => sub(settings::SettingsApi),
//! ))]
//! pub struct KeysApi;
//! ```
//!
//! The attribute's macro writes the `configure` function, so the builder
//! chain Archer reads elsewhere does not exist in the source. The table is
//! read instead: each entry is a route, `sub(T)` mounts another table under
//! the entry's path, and the table is placed where `.configure` names it.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};
use syn::{
    Item, LitStr, Token, bracketed, parenthesized,
    parse::{ParseStream, Parser},
    punctuated::Punctuated,
    spanned::Spanned,
};

use super::{handlers::*, model::*, routes::*};

/// How deep `sub(T)` nesting is followed; a table that mounts itself stops.
const MAX_NESTING: usize = 8;

/// A route table type and its entries.
pub(crate) struct RouteTable {
    pub(crate) crate_key: PathBuf,
    pub(crate) module: Vec<String>,
    pub(crate) name: String,
    pub(crate) file: PathBuf,
    pub(crate) entries: Vec<TableEntry>,
}

pub(crate) struct TableEntry {
    pub(crate) path: LitStr,
    /// `(method, handler path)`; method `sub` names a nested table type.
    pub(crate) targets: Vec<(String, Vec<String>)>,
}

/// A `.configure(<T as Routes>::configure)` call naming a table type.
#[derive(Debug, Clone)]
pub(crate) struct TableMount {
    pub(crate) segments: Vec<String>,
    pub(crate) crate_key: PathBuf,
    pub(crate) module: Vec<String>,
    pub(crate) prefix: String,
    pub(crate) inherited: Vec<AuthEvidence>,
    pub(crate) enclosing: Option<usize>,
}

const METHODS: [&str; 7] = ["get", "post", "put", "patch", "delete", "head", "options"];

/// The type a `.configure` argument names when it is a trait's `configure`
/// on a type: `<T as Routes>::configure` or `T::configure`.
pub(crate) fn configured_type(arg: &syn::Expr) -> Option<Vec<String>> {
    let syn::Expr::Path(path) = arg else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    if segments.last()? != "configure" {
        return None;
    }
    if let Some(qself) = &path.qself {
        let syn::Type::Path(ty) = &*qself.ty else {
            return None;
        };
        return Some(
            ty.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect(),
        );
    }
    let ty = &segments[..segments.len() - 1];
    // `admin::configure` is a function in a module, not a type's method.
    ty.last()
        .filter(|name| name.starts_with(|c: char| c.is_ascii_uppercase()))
        .map(|_| ty.to_vec())
}

/// Every route table declared on a struct or enum in the scanned files.
pub(crate) fn route_tables<'f>(
    files: impl Iterator<Item = (&'f ModuleKey, &'f Path, &'f syn::File)>,
) -> Vec<RouteTable> {
    let mut tables = Vec::new();
    for ((crate_key, module), file, syntax) in files {
        collect(&syntax.items, crate_key, module, file, &mut tables);
    }
    tables
}

fn collect(
    items: &[Item],
    crate_key: &Path,
    module: &[String],
    file: &Path,
    tables: &mut Vec<RouteTable>,
) {
    for item in items {
        let (attrs, ident) = match item {
            Item::Struct(item) => (&item.attrs, &item.ident),
            Item::Enum(item) => (&item.attrs, &item.ident),
            Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    let mut inner = module.to_vec();
                    inner.push(item.ident.to_string());
                    collect(items, crate_key, &inner, file, tables);
                }
                continue;
            }
            _ => continue,
        };
        for attribute in attrs {
            if let Some(entries) = table_entries(attribute) {
                tables.push(RouteTable {
                    crate_key: crate_key.to_path_buf(),
                    module: module.to_vec(),
                    name: ident.to_string(),
                    file: file.to_path_buf(),
                    entries,
                });
            }
        }
    }
}

/// The entries of a `routes(...)` list inside an attribute's arguments, if
/// it has one and every entry has the table shape.
fn table_entries(attribute: &syn::Attribute) -> Option<Vec<TableEntry>> {
    let syn::Meta::List(list) = &attribute.meta else {
        return None;
    };
    let mut tokens = list.tokens.clone().into_iter().peekable();
    while let Some(token) = tokens.next() {
        let proc_macro2::TokenTree::Ident(ident) = &token else {
            continue;
        };
        if ident != "routes" {
            continue;
        }
        let Some(proc_macro2::TokenTree::Group(group)) = tokens.peek() else {
            continue;
        };
        if group.delimiter() != proc_macro2::Delimiter::Parenthesis {
            continue;
        }
        let parsed = (|input: ParseStream| {
            Punctuated::<TableEntry, Token![,]>::parse_terminated_with(input, parse_entry)
        })
        .parse2(group.stream());
        return match parsed {
            Ok(entries) if !entries.is_empty() => Some(entries.into_iter().collect()),
            _ => None,
        };
    }
    None
}

fn parse_entry(input: ParseStream) -> syn::Result<TableEntry> {
    let path: LitStr = input.parse()?;
    input.parse::<Token![=>]>()?;
    let targets = if input.peek(syn::token::Bracket) {
        let content;
        bracketed!(content in input);
        Punctuated::<(String, Vec<String>), Token![,]>::parse_terminated_with(
            &content,
            parse_target,
        )?
        .into_iter()
        .collect()
    } else {
        vec![parse_target(input)?]
    };
    Ok(TableEntry { path, targets })
}

fn parse_target(input: ParseStream) -> syn::Result<(String, Vec<String>)> {
    let method: syn::Ident = input.parse()?;
    let content;
    parenthesized!(content in input);
    let target: syn::Path = content.parse()?;
    let method = method.to_string();
    if method != "sub" && !METHODS.contains(&method.as_str()) {
        return Err(syn::Error::new(method.span(), "not a route method"));
    }
    Ok((
        method,
        target
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect(),
    ))
}

/// The table a type path names from `crate_key`/`module`: a qualified path
/// through its module, else the one table of that name in the crate, else
/// the one in the workspace.
fn resolve_table(
    index: &HandlerIndex,
    tables: &[RouteTable],
    crate_key: &Path,
    module: &[String],
    segments: &[String],
) -> Option<usize> {
    let (name, qualifier) = segments.split_last()?;
    let unique = |matches: Vec<usize>| (matches.len() == 1).then(|| matches[0]);
    let named = |filter: &dyn Fn(&RouteTable) -> bool| {
        tables
            .iter()
            .enumerate()
            .filter(|(_, table)| &table.name == name && filter(table))
            .map(|(position, _)| position)
            .collect::<Vec<_>>()
    };
    let (target_crate, target_module) = if qualifier.is_empty() {
        (crate_key.to_path_buf(), module.to_vec())
    } else {
        index
            .resolve_module(
                crate_key,
                module,
                &UsePath {
                    segments: qualifier.to_vec(),
                    leading_colon: false,
                },
                0,
            )
            .unwrap_or_else(|| (PathBuf::new(), Vec::new()))
    };
    unique(named(&|table| {
        table.crate_key == target_crate && table.module == target_module
    }))
    .or_else(|| unique(named(&|table| table.crate_key == crate_key)))
    .or_else(|| unique(named(&|_| true)))
}

/// Routes of every mounted table, and the tables nothing mounts.
pub(crate) fn table_routes(
    index: &HandlerIndex,
    tables: &[RouteTable],
    mounts: &[TableMount],
) -> (Vec<Route>, Vec<String>) {
    let mut routes = Vec::new();
    let mut placed = HashSet::new();
    for mount in mounts {
        let Some(table) = resolve_table(
            index,
            tables,
            &mount.crate_key,
            &mount.module,
            &mount.segments,
        ) else {
            continue;
        };
        expand(
            index,
            tables,
            table,
            &mount.prefix,
            &mount.inherited,
            mount.enclosing,
            &mut Vec::new(),
            &mut placed,
            &mut routes,
        );
    }
    let unmounted = tables
        .iter()
        .enumerate()
        .filter(|(position, _)| !placed.contains(position))
        .map(|(_, table)| format!("{} ({})", table.name, table.file.display()))
        .collect();
    (routes, unmounted)
}

#[allow(clippy::too_many_arguments)]
fn expand(
    index: &HandlerIndex,
    tables: &[RouteTable],
    table: usize,
    prefix: &str,
    inherited: &[AuthEvidence],
    enclosing: Option<usize>,
    stack: &mut Vec<usize>,
    placed: &mut HashSet<usize>,
    routes: &mut Vec<Route>,
) {
    if stack.contains(&table) || stack.len() >= MAX_NESTING {
        return;
    }
    placed.insert(table);
    stack.push(table);
    let declared = &tables[table];
    for entry in &declared.entries {
        let path = join_paths(prefix, &entry.path.value());
        for (method, target) in &entry.targets {
            if method == "sub" {
                if let Some(nested) =
                    resolve_table(index, tables, &declared.crate_key, &declared.module, target)
                {
                    expand(
                        index, tables, nested, &path, inherited, enclosing, stack, placed, routes,
                    );
                }
                continue;
            }
            let handler_target = HandlerTarget::Path {
                segments: target.clone(),
                leading_colon: false,
            };
            let (definition, resolution) =
                index.resolve_handler_index(&declared.crate_key, &declared.module, &handler_target);
            let handler = target.last().cloned();
            let mut authorization = definition
                .map(|definition| index.definitions[definition].evidence.clone())
                .unwrap_or_default();
            add_inherited_evidence(&mut authorization, inherited, handler.as_deref());
            let mut unverified = Vec::new();
            if definition.is_none() {
                unverified.push(format!(
                    "handler `{}` named in the route table of `{}` could not be resolved",
                    target.join("::"),
                    declared.name
                ));
            }
            routes.push(Route {
                method: method.to_uppercase(),
                path: path.clone(),
                scope_prefix: prefix.to_owned(),
                authorization,
                handler_path: Some(target.join("::")),
                handler_resolution: Some(resolution),
                handler,
                line: entry.path.span().start().line,
                file: declared.file.clone(),
                unverified,
                requirement: Requirement::default(),
                resource_keys: Vec::new(),
                caller_use: Vec::new(),
                origin: RouteOrigin {
                    position: span_position(entry.path.span()),
                    attribute: None,
                    enclosing,
                    definition,
                    called: Vec::new(),
                    takes_credentials: false,
                    sees_request: false,
                    takes_nothing: false,
                    takes_data: false,
                    openapi: None,
                    unserved: false,
                    app: None,
                },
            });
        }
    }
    stack.pop();
}
