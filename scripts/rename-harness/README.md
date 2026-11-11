# Rename harness (P8)

Renames every identifier an app defines (functions, methods, types, traits,
enum variants, fields, consts, statics, parameters, `let` bindings, and
`{name}` placeholders in strings) to neutral tokens (`q0123`, `Q0456`), then
reruns Archer and compares the findings with the unrenamed run. A finding
that changes shows a decision that rests on a name.

Kept as written: module and crate names (they name files), and every name the
std/core/alloc, actix-*, futures-* and serde sources define (the API Archer
reads). `user_id`, `caller` and `sub` are removed from that keep list, since
they are app vocabulary that happens to occur in a library.

```sh
cargo build --release --manifest-path scripts/rename-harness/Cargo.toml
H=scripts/rename-harness/target/release/archer-rename-harness
$H keep keep.txt $RUST_SRC/std/src $RUST_SRC/core/src $RUST_SRC/alloc/src ~/.cargo/registry/src/*/actix-* ...
sed -i '/^\(user_id\|caller\|sub\)$/d' keep.txt
$H rename keep.txt <app> <renamed-copy>      # writes <renamed-copy>/.rename-map.tsv
archer --json <app> > o.json; archer --json <renamed-copy> > r.json   # run both from inside the tree
python3 rncmp.py o.json r.json <renamed-copy>/.rename-map.tsv
```

`rngate.sh` runs it over every fixture and a list of benchmark checkouts;
`rnev.py` lists which evidence disappears after renaming.
