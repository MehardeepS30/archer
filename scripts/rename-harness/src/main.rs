//! Rename harness for Archer (P8).
//!
//! `rn keep <out.txt> <dir>...`   names defined in library sources (kept as-is)
//! `rn rename <keep.txt> <src> <dst>`  copy <src> to <dst>, renaming every
//!     identifier the project defines (fns, methods, types, traits, variants,
//!     fields, consts, statics, params, let bindings) that is not in keep.txt,
//!     consistently in every .rs file, and `{name}` placeholders in strings.
//!     Writes <dst>/.rename-map.tsv.
use proc_macro2::{TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use syn::visit::Visit;
use walkdir::WalkDir;

struct Defs(BTreeSet<String>, bool);

impl<'a> Visit<'a> for Defs {
    fn visit_item_fn(&mut self, n: &'a syn::ItemFn) { self.0.insert(n.sig.ident.to_string()); syn::visit::visit_item_fn(self, n) }
    fn visit_impl_item_fn(&mut self, n: &'a syn::ImplItemFn) { self.0.insert(n.sig.ident.to_string()); syn::visit::visit_impl_item_fn(self, n) }
    fn visit_trait_item_fn(&mut self, n: &'a syn::TraitItemFn) { self.0.insert(n.sig.ident.to_string()); syn::visit::visit_trait_item_fn(self, n) }
    fn visit_impl_item_const(&mut self, n: &'a syn::ImplItemConst) { self.0.insert(n.ident.to_string()); syn::visit::visit_impl_item_const(self, n) }
    fn visit_impl_item_type(&mut self, n: &'a syn::ImplItemType) { self.0.insert(n.ident.to_string()); syn::visit::visit_impl_item_type(self, n) }
    fn visit_trait_item_type(&mut self, n: &'a syn::TraitItemType) { self.0.insert(n.ident.to_string()); syn::visit::visit_trait_item_type(self, n) }
    fn visit_trait_item_const(&mut self, n: &'a syn::TraitItemConst) { self.0.insert(n.ident.to_string()); syn::visit::visit_trait_item_const(self, n) }
    fn visit_item_struct(&mut self, n: &'a syn::ItemStruct) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_struct(self, n) }
    fn visit_item_enum(&mut self, n: &'a syn::ItemEnum) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_enum(self, n) }
    fn visit_item_union(&mut self, n: &'a syn::ItemUnion) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_union(self, n) }
    fn visit_item_trait(&mut self, n: &'a syn::ItemTrait) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_trait(self, n) }
    fn visit_item_type(&mut self, n: &'a syn::ItemType) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_type(self, n) }
    fn visit_item_const(&mut self, n: &'a syn::ItemConst) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_const(self, n) }
    fn visit_item_static(&mut self, n: &'a syn::ItemStatic) { self.0.insert(n.ident.to_string()); syn::visit::visit_item_static(self, n) }
    fn visit_variant(&mut self, n: &'a syn::Variant) { self.0.insert(n.ident.to_string()); syn::visit::visit_variant(self, n) }
    fn visit_field(&mut self, n: &'a syn::Field) { if !self.1 && let Some(i) = &n.ident { self.0.insert(i.to_string()); } syn::visit::visit_field(self, n) }
    fn visit_pat_ident(&mut self, n: &'a syn::PatIdent) { if !self.1 { self.0.insert(n.ident.to_string()); } syn::visit::visit_pat_ident(self, n) }
    fn visit_item_mod(&mut self, n: &'a syn::ItemMod) { if self.1 { self.0.insert(n.ident.to_string()); } syn::visit::visit_item_mod(self, n) }
    fn visit_item_macro(&mut self, n: &'a syn::ItemMacro) { if let Some(i) = &n.ident { self.0.insert(i.to_string()); } syn::visit::visit_item_macro(self, n) }
}

struct Mods(Vec<String>);
impl<'a> Visit<'a> for Mods {
    fn visit_item_mod(&mut self, n: &'a syn::ItemMod) { self.0.push(n.ident.to_string()); syn::visit::visit_item_mod(self, n) }
}

fn rs_files(dir: &Path) -> Vec<std::path::PathBuf> {
    WalkDir::new(dir).into_iter().filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs"))
        .filter(|e| !e.path().components().any(|c| c.as_os_str() == "target" || c.as_os_str() == ".git"))
        .map(|e| e.into_path()).collect()
}

fn defs_of(files: &[std::path::PathBuf], lib: bool) -> BTreeSet<String> {
    let mut d = Defs(BTreeSet::new(), lib);
    for f in files {
        let Ok(src) = std::fs::read_to_string(f) else { continue };
        if let Ok(file) = syn::parse_file(&src) { d.visit_file(&file); }
    }
    d.0
}

const RESERVED: &[&str] = &["self", "Self", "super", "crate", "main", "_"];

fn placeholder_rename(lit: &str, map: &BTreeMap<String, String>) -> Option<String> {
    if !(lit.starts_with('"') || lit.starts_with("r\"") || lit.starts_with("r#")) || !lit.contains('{') { return None; }
    let mut out = String::new();
    let mut changed = false;
    let b: Vec<char> = lit.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '{' && i + 1 < b.len() && b[i + 1] == '{' { out.push_str("{{"); i += 2; continue; }
        if b[i] == '{' {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_alphanumeric() || b[j] == '_') { j += 1; }
            let name: String = b[i + 1..j].iter().collect();
            if j < b.len() && (b[j] == '}' || b[j] == ':') && let Some(r) = map.get(&name) {
                out.push('{'); out.push_str(r); changed = true; i = j; continue;
            }
        }
        out.push(b[i]); i += 1;
    }
    changed.then_some(out)
}

type Edit = (usize, usize, usize, String);

fn walk(ts: TokenStream, map: &BTreeMap<String, String>, edits: &mut Vec<Edit>) {
    for tt in ts {
        match tt {
            TokenTree::Group(g) => walk(g.stream(), map, edits),
            TokenTree::Ident(id) => {
                let s = id.to_string();
                if let Some(r) = map.get(&s) {
                    let st = id.span().start();
                    edits.push((st.line, st.column, s.chars().count(), r.clone()));
                }
            }
            TokenTree::Literal(l) => {
                let s = l.to_string();
                if let Some(r) = placeholder_rename(&s, map) {
                    let st = l.span().start();
                    let en = l.span().end();
                    if st.line == en.line { edits.push((st.line, st.column, s.chars().count(), r)); }
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a[1].as_str() {
        "keep" => {
            let mut all = BTreeSet::new();
            for d in &a[3..] { all.extend(defs_of(&rs_files(Path::new(d)), true)); }
            std::fs::write(&a[2], all.into_iter().collect::<Vec<_>>().join("\n")).unwrap();
        }
        "rename" => {
            let keep: HashSet<String> = std::fs::read_to_string(&a[2]).unwrap().lines().map(String::from).collect();
            let (src, dst) = (Path::new(&a[3]), Path::new(&a[4]));
            let files = rs_files(src);
            let defs = defs_of(&files, false);
            // Module and crate names stay: they name files and directories.
            let mut keep = keep;
            keep.extend(defs_of(&files, true).into_iter().filter(|_| false));
            for f in &files {
                if let Some(stem) = f.file_stem() { keep.insert(stem.to_string_lossy().replace('-', "_")); }
                for c in f.strip_prefix(src).unwrap().components() { keep.insert(c.as_os_str().to_string_lossy().replace('-', "_")); }
                if let Ok(text) = std::fs::read_to_string(f) && let Ok(file) = syn::parse_file(&text) {
                    let mut m = Mods(Vec::new()); m.visit_file(&file); keep.extend(m.0);
                }
            }
            for e in WalkDir::new(src).into_iter().filter_map(|e| e.ok()).filter(|e| e.file_name() == "Cargo.toml") {
                if let Ok(t) = std::fs::read_to_string(e.path()) { for l in t.lines() { if let Some(v) = l.trim().strip_prefix("name") { let v = v.trim_start_matches([' ', '=']).trim_matches(['"', ' ']); keep.insert(v.replace('-', "_")); } } }
            }
            let mut map = BTreeMap::new();
            for (i, n) in defs.iter().filter(|n| !keep.contains(*n) && !RESERVED.contains(&n.as_str()) && !n.starts_with("r#")).enumerate() {
                let up = n.chars().next().unwrap().is_uppercase();
                map.insert(n.clone(), format!("{}{:04}", if up { "Q" } else { "q" }, i));
            }
            for e in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
                let rel = e.path().strip_prefix(src).unwrap();
                if rel.components().any(|c| c.as_os_str() == ".git" || c.as_os_str() == "target") { continue; }
                let out = dst.join(rel);
                if e.file_type().is_dir() { std::fs::create_dir_all(&out).unwrap(); continue; }
                if !e.file_type().is_file() { continue; }
                let is_rs = e.path().extension().is_some_and(|x| x == "rs");
                if !is_rs { let _ = std::fs::copy(e.path(), &out); continue; }
                let Ok(text) = std::fs::read_to_string(e.path()) else { let _ = std::fs::copy(e.path(), &out); continue };
                let Ok(ts) = text.parse::<TokenStream>() else { eprintln!("untokenized {}", rel.display()); std::fs::write(&out, &text).unwrap(); continue };
                let mut edits = Vec::new();
                walk(ts, &map, &mut edits);
                let mut lines: Vec<String> = text.split('\n').map(String::from).collect();
                edits.sort_by(|x, y| (y.0, y.1).cmp(&(x.0, x.1)));
                for (line, col, len, rep) in edits {
                    let l = &mut lines[line - 1];
                    let chars: Vec<char> = l.chars().collect();
                    if col + len > chars.len() { eprintln!("skip edit {}:{}:{}", rel.display(), line, col); continue; }
                    *l = chars[..col].iter().collect::<String>() + &rep + &chars[col + len..].iter().collect::<String>();
                }
                std::fs::write(&out, lines.join("\n")).unwrap();
            }
            let tsv: String = map.iter().map(|(k, v)| format!("{k}\t{v}\n")).collect();
            std::fs::write(dst.join(".rename-map.tsv"), tsv).unwrap();
            eprintln!("renamed {} names, kept {} defined names", map.len(), defs.len() - map.len());
        }
        _ => panic!("usage"),
    }
}
