import json,sys,collections
# which original evidence (kind, mechanism) disappears or changes kind after renaming
L=sys.argv[1]
for w in sys.argv[2:]:
    o=json.load(open(f'/root/g/rn/{L}/{w}.o.json')); r=json.load(open(f'/root/g/rn/{L}/{w}.r.json'))
    def idx(j): return {(x['method'],x['file'],x['line']):x for x in j['routes']}
    io,ir=idx(o),idx(r); c=collections.Counter(); tiers=collections.Counter()
    for k,x in io.items():
        y=ir.get(k)
        if not y: c[('route missing',)]+=1; continue
        tiers[(x.get('tier'),y.get('tier'))]+=1
        ys={(a['file'],a['line'],a['kind']) for a in y['authorization']}
        for a in x['authorization']:
            if a['kind']=='Unknown': continue
            if (a['file'],a['line'],a['kind']) not in ys:
                yk=[b['kind'] for b in y['authorization'] if (b['file'],b['line'])==(a['file'],a['line'])]
                c[(a['kind'],a['mechanism'][:50],'->',','.join(yk) or 'gone')]+=1
    print('==',w,'tier changes',{k:v for k,v in tiers.items() if k[0]!=k[1]})
    for k,v in c.most_common(12): print('  ',v,k)
