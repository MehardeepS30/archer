//! The order of an application's role types, where the code states one:
//! an enum deriving `PartialOrd`/`Ord`, whose variants rank by their
//! explicit discriminants (`Owner = 2`) or, without them, by declaration
//! order. With it, `user.role >= Role::Editor` admits a set of roles
//! (`editor` and every role above it), comparable with an allow-list such
//! as `matches!(user.role, Role::Editor | Role::Chief)`.

use std::{cell::RefCell, collections::HashMap};
use syn::{Expr, Item};

use super::evidence::{camel_case_words, normalize_key};

/// An ordered role type: its variants' keys, lowest rank first.
#[derive(Debug, Clone)]
struct Order {
    ranked: Vec<(i64, String)>,
}

thread_local! {
    static ORDERS: RefCell<HashMap<String, Order>> = RefCell::new(HashMap::new());
}

fn variant_key(variant: &str) -> Option<String> {
    normalize_key(&camel_case_words(variant).join("_"))
}

pub(crate) fn index_role_orders<'a>(files: impl IntoIterator<Item = &'a syn::File>) {
    let mut orders = HashMap::new();
    for file in files {
        collect(&file.items, &mut orders);
    }
    ORDERS.with(|map| *map.borrow_mut() = orders);
}

fn derives_order(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        attribute.path().is_ident("derive")
            && quote::ToTokens::to_token_stream(&attribute.meta)
                .to_string()
                .split(|character: char| !character.is_alphanumeric())
                .any(|word| word == "PartialOrd" || word == "Ord")
    })
}

fn discriminant(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(value), .. }) => value.base10_parse().ok(),
        Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Neg(_)) => discriminant(&unary.expr).map(|value| -value),
        _ => None,
    }
}

fn collect(items: &[Item], orders: &mut HashMap<String, Order>) {
    for item in items {
        match item {
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect(items, orders);
                }
            }
            Item::Enum(item) if derives_order(&item.attrs) && item.variants.len() >= 2 => {
                // Every variant has an explicit discriminant, or none does
                // and declaration order ranks them.
                let explicit: Vec<Option<i64>> = item
                    .variants
                    .iter()
                    .map(|variant| variant.discriminant.as_ref().and_then(|(_, expr)| discriminant(expr)))
                    .collect();
                let ranks: Vec<i64> = if explicit.iter().all(Option::is_some) {
                    explicit.into_iter().flatten().collect()
                } else if explicit.iter().all(Option::is_none) {
                    (0..item.variants.len() as i64).collect()
                } else {
                    continue;
                };
                let mut ranked: Vec<(i64, String)> = item
                    .variants
                    .iter()
                    .zip(ranks)
                    .filter_map(|(variant, rank)| Some((rank, variant_key(&variant.ident.to_string())?)))
                    .collect();
                ranked.sort();
                orders.insert(item.ident.to_string(), Order { ranked });
            }
            _ => {}
        }
    }
}

/// The roles a comparison of a role with `Type::Variant` admits, when the
/// type is ordered: `at_least` keeps the variant itself, otherwise only the
/// ones above it.
pub(crate) fn admitted_from(path: &syn::Path, at_least: bool) -> Option<Vec<String>> {
    let segments = &path.segments;
    let owner = segments.iter().nth_back(1)?.ident.to_string();
    let variant = variant_key(&segments.last()?.ident.to_string())?;
    ORDERS.with(|map| {
        let map = map.borrow();
        let order = map.get(&owner)?;
        let rank = order.ranked.iter().find(|(_, key)| *key == variant)?.0;
        Some(
            order
                .ranked
                .iter()
                .filter(|(other, _)| if at_least { *other >= rank } else { *other > rank })
                .map(|(_, key)| key.clone())
                .collect(),
        )
    })
}

/// The roles an ordering comparison admits: `role >= T::V` and `T::V <=
/// role` admit `V` and above; `role > T::V` admits only above. A rejecting
/// `role < T::V` admits `V` and above too: the comparison names the
/// threshold, the branch decides which side passes, and a check that lets
/// lower roles through and stops higher ones is not written this way.
pub(crate) fn ordering_admits(binary: &syn::ExprBinary) -> Option<(Vec<String>, &Expr)> {
    let constant = |expr: &Expr| match expr {
        Expr::Path(path) if path.path.segments.len() >= 2 => Some(path.path.clone()),
        Expr::Reference(reference) => match &*reference.expr {
            Expr::Path(path) if path.path.segments.len() >= 2 => Some(path.path.clone()),
            _ => None,
        },
        _ => None,
    };
    use syn::BinOp::{Ge, Gt, Le, Lt};
    // Normalized to `role OP constant`.
    let (role, threshold, op) = match (constant(&binary.left), constant(&binary.right)) {
        (None, Some(path)) => (&*binary.left, path, binary.op),
        (Some(path), None) => (
            &*binary.right,
            path,
            match binary.op {
                Ge(token) => Le(syn::Token![<=](token.spans)),
                Gt(token) => Lt(syn::Token![<](token.spans)),
                Le(token) => Ge(syn::Token![>=](token.spans)),
                Lt(token) => Gt(syn::Token![>](token.spans)),
                other => other,
            },
        ),
        _ => return None,
    };
    let admitted = match op {
        Ge(_) | Lt(_) => admitted_from(&threshold, true)?,
        Gt(_) | Le(_) => admitted_from(&threshold, false)?,
        _ => return None,
    };
    Some((admitted, role))
}

/// The path of the collection a route acts on: `/teams` for `/teams/{id}`
/// and for `/teams`.
fn collection(path: &str) -> &str {
    let mut path = path.trim_end_matches('/');
    while let Some((head, last)) = path.rsplit_once('/') {
        if last.starts_with('{') {
            path = head;
        } else {
            break;
        }
    }
    path
}

/// The delete check: a DELETE whose allow-list admits roles that every
/// update of the same resource (PUT or PATCH on its collection or a record
/// of it) refuses. Removing a record does at least as much as changing
/// it, so a caller who may not change it should not remove it either;
/// one update is support enough, since the order of the two operations
/// is the evidence, not the peers' number.
pub(crate) fn delete_admits_more(
    routes: &[super::model::Route],
    peer_groups: &mut Vec<super::model::PeerGroup>,
    invariants: &mut Vec<super::model::AuthorizationInvariant>,
    finding_details: &mut Vec<super::model::Finding>,
) {
    use super::model::*;
    let routes = super::drift::unique_routes(routes.iter());
    let allow_list = |route: &Route| -> Option<Vec<String>> {
        let requirement = Requirement::of(route);
        (route.best_tier() == EvidenceTier::Privilege
            && !requirement.unverified
            && super::drift::is_allow_list(route, &requirement))
        .then_some(requirement.roles)
    };
    let reported: std::collections::HashSet<_> = finding_details
        .iter()
        .map(|finding| (finding.suspicious_route.method.clone(), finding.suspicious_route.path.clone()))
        .collect();
    let mut found = Vec::new();
    for (index, route) in routes.iter().enumerate() {
        if route.method != "DELETE" || reported.contains(&(route.method.clone(), route.path.clone())) {
            continue;
        }
        let Some(own) = allow_list(route) else {
            continue;
        };
        let family = collection(&route.path);
        let updates: Vec<(usize, Vec<String>)> = routes
            .iter()
            .enumerate()
            .filter(|(other, peer)| {
                *other != index
                    && (peer.method == "PUT" || peer.method == "PATCH")
                    && collection(&peer.path) == family
                    && peer.handler != route.handler
            })
            .map(|(other, peer)| (other, allow_list(peer)))
            .map(|(other, roles)| roles.map(|roles| (other, roles)))
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        if updates.is_empty() {
            continue;
        }
        let extra: Vec<String> = own
            .iter()
            .filter(|role| updates.iter().all(|(_, roles)| !roles.contains(role)))
            .cloned()
            .collect();
        let narrower = updates.iter().all(|(_, roles)| roles.iter().all(|role| own.contains(role)));
        if extra.is_empty() || !narrower {
            continue;
        }
        found.push((index, own, updates, extra));
    }
    let list = |roles: &[String]| roles.iter().map(|role| format!("`{role}`")).collect::<Vec<_>>().join(", ");
    for (index, own, updates, extra) in found {
        let route = routes[index];
        let id = format!("peer-group-{:03}", peer_groups.len() + 1);
        let mut members: Vec<RouteReference> = vec![route.into()];
        members.extend(updates.iter().map(|(other, _)| routes[*other].into()));
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: format!("the delete and the updates of {}", collection(&route.path)),
            prefix: collection(&route.path).to_string(),
            level: GroupLevel::Linked,
            method_class: MethodClass::Write,
            routes: members,
        });
        let peer_roles: Vec<String> = {
            let mut roles: Vec<String> = updates.iter().flat_map(|(_, roles)| roles.iter().cloned()).collect();
            roles.sort();
            roles.dedup();
            roles
        };
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Deleting a record of {} admits no role that updating it refuses.",
                collection(&route.path)
            ),
            total_routes: updates.len() + 1,
            routes_with_authorization: updates.len(),
            routes_without_authorization: 1,
            evidence_patterns: peer_roles.clone(),
            strength: AuthStrength::Medium,
            expected_tier: Some(EvidenceTier::Privilege),
            dominant_requirement: peer_roles.first().cloned(),
        };
        invariants.push(invariant.clone());
        let updated: Vec<String> =
            updates.iter().map(|(other, _)| format!("{} {}", routes[*other].method, routes[*other].path)).collect();
        finding_details.push(Finding {
            peer_group_id: id,
            category: FindingCategory::WeakerAuthorization,
            severity: Severity::Medium,
            rationale: format!(
                "Deletes for any of {} where updating the same resource ({}) admits only {}: it lets {} remove what they may not change. Dismiss if the difference is intended.",
                list(&own),
                updated.join(", "),
                list(&peer_roles),
                list(&extra),
            ),
            invariant,
            suspicious_route: route.into(),
            suspicious_route_tier: route.best_tier(),
            expected_tier: EvidenceTier::Privilege,
            suspicious_route_evidence: route.authorization.clone(),
            evidence: Default::default(),
            authorized_peer_routes: updates.iter().map(|(other, _)| routes[*other].into()).collect(),
        });
    }
}
