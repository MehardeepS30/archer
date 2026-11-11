#!/bin/bash
# usage: rngate.sh <label> <archer-bin> [VAR=val...]   (fixtures + benchmark repos in RNREPOS)
L=$1; B=$2; shift 2
G=~/g; RN=~/rn/target/release/rn; FX=~/w/archer/tests/fixtures
mkdir -p $G/rn/$L
# fixtures: prepare once
if [ ! -d $G/rn/fx ]; then
  for f in $(find $FX -name '*.rs'); do n=$(basename $f .rs); mkdir -p $G/rn/fx/orig/$n; cp $f $G/rn/fx/orig/$n/; $RN rename $G/keep.txt $G/rn/fx/orig/$n $G/rn/fx/ren/$n 2>/dev/null; done
fi
for d in $G/rn/fx/orig/*; do n=$(basename $d)
  (cd $d && env "$@" $B --json . > $G/rn/$L/fx-$n.o.json 2>/dev/null)
  (cd $G/rn/fx/ren/$n && env "$@" $B --json . > $G/rn/$L/fx-$n.r.json 2>/dev/null)
  python3 $G/scripts/rncmp.py $G/rn/$L/fx-$n.o.json $G/rn/$L/fx-$n.r.json $G/rn/fx/ren/$n/.rename-map.tsv fx-$n
done > $G/rn/$L/fixtures.jsonl
for w in ${RNREPOS:-B-z2p B-realworld B-rustypaste B-lldap B-lemmy B-qdrant}; do
  [ -d $G/rn/repo-ren/$w ] || $RN rename $G/keep.txt $G/wt/$w $G/rn/repo-ren/$w 2>$G/rn/repo-ren-$w.log
  (cd $G/wt/$w && env "$@" timeout 900 $B --json . > $G/rn/$L/$w.o.json 2>/dev/null)
  (cd $G/rn/repo-ren/$w && env "$@" timeout 900 $B --json . > $G/rn/$L/$w.r.json 2>/dev/null)
  python3 $G/scripts/rncmp.py $G/rn/$L/$w.o.json $G/rn/$L/$w.r.json $G/rn/repo-ren/$w/.rename-map.tsv $w
done > $G/rn/$L/repos.jsonl
python3 - $G/rn/$L <<'PY'
import json,sys
for f in ('fixtures','repos'):
    rows=[json.loads(l) for l in open(f'{sys.argv[1]}/{f}.jsonl')]
    o=sum(r['orig'] for r in rows); s=sum(r['same'] for r in rows); u=sum(r['union'] for r in rows)
    print(f, 'orig',o,'renamed',sum(r['renamed'] for r in rows),'same',s,'sev',sum(r['sev_changed'] for r in rows),'lost',sum(r['lost'] for r in rows),'new',sum(r['new'] for r in rows), f'match {100*s/max(u,1):.1f}% of {u}')
    if f=='repos':
        for r in rows: print('  ',r['label'],'orig',r['orig'],'same',r['same'],'sev',r['sev_changed'],'lost',r['lost'],'new',r['new'],'routes',r['routes'])
PY
