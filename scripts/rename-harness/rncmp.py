"""Compare Archer findings on an original tree and its renamed copy.
usage: rncmp.py <orig.json> <renamed.json> <rename-map.tsv> [label]"""
import json,re,sys
o=json.load(open(sys.argv[1])); r=json.load(open(sys.argv[2]))
inv={}
for l in open(sys.argv[3]):
    k,v=l.rstrip('\n').split('\t'); inv[v]=k
def unmap(p): return re.sub(r'\{([Qq]\d{4})',lambda m:'{'+inv.get(m.group(1),m.group(1)),p or '')
def key(f,ren):
    s=f['suspicious_route']; p=s['path']; p=unmap(p) if ren else p
    loc=(s.get('location') or {}) if isinstance(s.get('location'),dict) else {}
    return (s['method'],p,s.get('file') or loc.get('file'),s.get('line') or loc.get('line'))
fo={key(f,0):f['severity'] for f in o['finding_details']}
fr={key(f,1):f['severity'] for f in r['finding_details']}
same=sum(1 for k in fo if fr.get(k)==fo[k]); sev=sum(1 for k in fo if k in fr and fr[k]!=fo[k])
lost=[k for k in fo if k not in fr]; new=[k for k in fr if k not in fo]
u=len(set(fo)|set(fr))
lab=sys.argv[4] if len(sys.argv)>4 else ''
ro=len(o['routes']); rr=len(r['routes'])
print(json.dumps({'label':lab,'orig':len(fo),'renamed':len(fr),'same':same,'sev_changed':sev,'lost':len(lost),'new':len(new),'union':u,'routes':[ro,rr],
  'details':[('sev',k,fo[k],fr[k]) for k in fo if k in fr and fr[k]!=fo[k]]+[('lost',k,fo[k]) for k in lost]+[('new',k,fr[k]) for k in new]}))
