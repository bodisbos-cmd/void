"""Build Voidling as a self-contained glTF 2.0 binary with real triangle geometry.
Uses only the Python standard library and creates the cached GLB on first request.
"""
from __future__ import annotations
import json, math, struct
from functools import lru_cache

V = tuple[float, float, float]
GROUPS: dict[str, list[tuple[list[V], list[V], list[tuple[int,int,int]]]]] = {}

def add(name, mesh):
    GROUPS.setdefault(name, []).append(mesh)

def unit(a: V) -> V:
    d=math.sqrt(sum(x*x for x in a)) or 1.0
    return tuple(x/d for x in a)
def addv(a: V,b: V)->V:return tuple(a[i]+b[i] for i in range(3))
def subv(a: V,b: V)->V:return tuple(a[i]-b[i] for i in range(3))
def mulv(a: V,s: float)->V:return tuple(x*s for x in a)
def cross(a: V,b: V)->V:return(a[1]*b[2]-a[2]*b[1],a[2]*b[0]-a[0]*b[2],a[0]*b[1]-a[1]*b[0])

def ellipsoid(center: V,radii: V,lat: int=20,lon: int=32,deform=False):
    p=[];n=[];f=[]
    for y in range(lat+1):
        th=math.pi*y/lat
        for x in range(lon+1):
            ph=2*math.pi*x/lon; nx=math.sin(th)*math.cos(ph); ny=math.cos(th); nz=math.sin(th)*math.sin(ph)
            if deform:
                nx*=1-.075*max(0,-ny); ny*=1+.035*max(0,ny); nz+=.022*nx+.012*math.sin(ny*4)
            p.append((center[0]+radii[0]*nx,center[1]+radii[1]*ny,center[2]+radii[2]*nz))
            n.append(unit((nx/radii[0],ny/radii[1],nz/radii[2])))
    for y in range(lat):
        for x in range(lon):
            a=y*(lon+1)+x;b=a+lon+1;f.extend(((a,b,a+1),(a+1,b,b+1)))
    return p,n,f

def tube(q, radius, sides=9, steps=25, taper=.08, flatten=(.78,1.,1.)):
    p=[];n=[];f=[]
    for i in range(steps+1):
        t=i/steps;u=1-t
        c=tuple(u**3*q[0][k]+3*u*u*t*q[1][k]+3*u*t*t*q[2][k]+t**3*q[3][k] for k in range(3))
        d=unit(tuple(3*u*u*(q[1][k]-q[0][k])+6*u*t*(q[2][k]-q[1][k])+3*t*t*(q[3][k]-q[2][k]) for k in range(3)))
        ref=(0.,0.,1.) if abs(d[1])>.88 else (0.,1.,0.);a=unit(cross(d,ref));b=unit(cross(d,a))
        rr=radius*(taper+(1-taper)*((1-t)**.72))
        for j in range(sides):
            ang=2*math.pi*j/sides;radial=unit(addv(mulv(a,math.cos(ang)*flatten[0]),mulv(b,math.sin(ang)*flatten[1])))
            p.append(addv(c,mulv(radial,rr)));n.append(radial)
    for i in range(steps):
        for j in range(sides):
            a=i*sides+j;b=i*sides+(j+1)%sides;c=(i+1)*sides+j;d=(i+1)*sides+(j+1)%sides
            f.extend(((a,b,c),(b,d,c)))
    p.extend((q[0],q[3]));n.extend((unit(subv(q[0],q[1])),unit(subv(q[3],q[2]))))
    first=len(p)-2;last=len(p)-1
    for j in range(sides):
        f.append((first,(j+1)%sides,j));base=steps*sides;f.append((last,base+j,base+(j+1)%sides))
    return p,n,f

def almond(center,rx,ry,depth,tilt=0.,rings=10,sides=32):
    """A thin, tapered lens surface; keep depth low so the eyes read as inlaid light, not eyeballs."""
    p=[];n=[];f=[]
    for back in (False,True):
        for ir in range(rings+1):
            r=ir/rings
            for j in range(sides):
                t=2*math.pi*j/sides;cx=math.cos(t);sy=math.sin(t)
                # Stronger horizontal taper makes the ends sharp and almond-shaped.
                x=rx*r*cx*(abs(cx)**.58);y=ry*r*sy*(abs(sy)**.06)
                z=(-.16 if back else 1.)*depth*math.sqrt(max(0.,1-r*r))
                xx=x*math.cos(tilt)-y*math.sin(tilt);yy=x*math.sin(tilt)+y*math.cos(tilt)
                p.append((center[0]+xx,center[1]+yy,center[2]+z))
                n.append(unit((xx/(rx*rx),yy/(ry*ry),z/(depth*depth+1e-9))))
        off=(rings+1)*sides if back else 0
        for ir in range(rings):
            for j in range(sides):
                a=off+ir*sides+j;b=off+ir*sides+(j+1)%sides;c=off+(ir+1)*sides+j;d=off+(ir+1)*sides+(j+1)%sides
                f.extend(((a,c,b),(b,c,d)) if not back else ((a,b,c),(b,d,c)))
    off=(rings+1)*sides
    for j in range(sides):
        a=rings*sides+j;b=rings*sides+(j+1)%sides;c=off+rings*sides+j;d=off+rings*sides+(j+1)%sides
        f.extend(((a,b,c),(b,d,c)))
    return p,n,f

def blade(q, width, sides=8, steps=28, tip=.035, thickness=.024, axis=(0.,0.,1.)):
    """Swept, double-sided leaf/ribbon mesh for the character's flowing chrome fins."""
    p=[]; n=[]; f=[]
    across=sides+1
    for face in (1.,-1.):
        offset=len(p)
        for i in range(steps+1):
            t=i/steps; u=1-t
            c=tuple(u**3*q[0][k]+3*u*u*t*q[1][k]+3*u*t*t*q[2][k]+t**3*q[3][k] for k in range(3))
            tangent=unit(tuple(3*u*u*(q[1][k]-q[0][k])+6*u*t*(q[2][k]-q[1][k])+3*t*t*(q[3][k]-q[2][k]) for k in range(3)))
            ref=axis if abs(sum(tangent[k]*axis[k] for k in range(3)))<.90 else (0.,1.,0.)
            lateral=unit(cross(tangent,ref)); normal=unit(cross(lateral,tangent))
            profile=tip+(1.-tip)*(max(0.,math.sin(math.pi*t))**.58)
            for j in range(across):
                v=2*j/sides-1
                breadth=width*profile*(1.-.18*v*v)
                camber=thickness*profile*math.sqrt(max(0.,1-v*v))*.55
                pos=addv(addv(c,mulv(lateral,v*breadth)),mulv(normal,face*camber))
                p.append(pos); n.append(unit(addv(mulv(normal,face),mulv(lateral,-v*.13))))
        for i in range(steps):
            for j in range(sides):
                a=offset+i*across+j; b=a+across; c=a+1; d=b+1
                f.extend(((a,b,c),(c,b,d)))
    return p,n,f

# Reference-led silhouette: a large smooth hood, tucked torso, a single high crown
# sweep, broad cheek flares, and a few layered liquid-metal tails.
add('void-shell',ellipsoid((-.015,.25,0),(.86,.755,.655),40,64,True))
# Fuller, softly tapered torso: the reference reads as one small pear-like body, not two stacked beads.
add('void-shell',ellipsoid((0,-.49,.012),(.285,.305,.222),28,40,True))

# A tucked, low-gloss connection rather than a bundle of thin wires.
add('liquid-chrome',tube(((-.15,-.37,-.08),(-.29,-.49,-.16),(-.30,-.61,-.19),(-.20,-.70,-.12)),.024,8,22,.12))
add('liquid-chrome',tube(((.15,-.37,-.08),(.29,-.49,-.16),(.30,-.61,-.19),(.20,-.70,-.12)),.024,8,22,.12))

# Broad cowl/crown blade. It rises from behind the hood and curls back toward
# the face; the large ribbon silhouette is intentional, not a horn made from a tube.
# Wider swept crown ribbon: attached at the upper-left shell, arcing over the head, and curling down the far side.
add('liquid-chrome',blade(((-.40,.45,.52),(-.65,1.10,.32),(.18,1.70,.015),(.64,.88,.14)),.115,16,48,.028,.035))
# Outer cheek fins flare from the hood and taper into soft tips.
# Shell-hugging cheek fins: keep them below the crown so they read as swept chrome edges, not round ears.
add('liquid-chrome',blade(((-.61,.15,.49),(-1.03,.34,.42),(-1.05,.70,.20),(-.75,.78,.20)),.112,12,38,.035,.035))
add('liquid-chrome',blade(((.57,.15,.46),(.95,.36,.38),(.91,.63,.20),(.70,.72,.16)),.095,12,36,.035,.032))
# Smaller inner curls create a layered, hooked silhouette close to the shell.
add('liquid-chrome',blade(((-.59,.00,.50),(-.91,.24,.44),(-.78,.50,.34),(-.50,.48,.42)),.078,10,32,.035,.029))
# The signature cheek cowl sweeps across the near side of the face and hugs the shell instead of forming a separate ear.
add('liquid-chrome',blade(((-.78,.20,.32),(-1.00,.32,.40),(-.79,-.08,.56),(-.48,-.02,.61)),.120,14,42,.025,.032))
# Rear planes remain offset in depth so the model still reads cleanly from side and back views.
add('liquid-chrome',blade(((-.47,.18,-.34),(-.87,.42,-.38),(-.73,.82,-.30),(-.32,.93,-.18)),.155,10,34,.035,.036))
add('liquid-chrome',blade(((.47,.18,-.34),(.84,.40,-.38),(.69,.77,-.30),(.32,.90,-.18)),.142,10,34,.035,.034))

# One low curved band wraps the torso, then four broad ribbons form an orderly tail silhouette.
add('liquid-chrome',blade(((-.18,-.35,.22),(-.55,-.25,.23),(-.62,-.49,.12),(-.31,-.64,.09)),.082,10,30,.06,.028))
# A slender shoulder-level sweep passes behind the torso and emerges on both sides like the reference's liquid orbit.
add('liquid-chrome',blade(((-.62,-.22,.07),(-1.02,-.02,.10),(.91,-.17,-.12),(.69,-.43,-.06)),.040,10,44,.025,.018))

# Four distinct, wider S-curved ribbons that taper into flowing tips instead of thin straight tendrils.
tails=[
 ((-.12,-.56,.20),(-.40,-.79,.34),(-.16,-1.10,.23),(-.60,-1.40,-.015)),
 ((-.035,-.62,.25),(-.24,-.88,.39),(.015,-1.13,.21),(-.14,-1.49,.015)),
 ((.085,-.61,.22),(.33,-.82,.34),(.08,-1.11,.18),(.39,-1.38,-.02)),
 ((.18,-.55,.14),(.51,-.69,.24),(.25,-.99,.08),(.68,-1.29,-.06)),
]
for q,width in zip(tails,(.145,.128,.146,.122)):
    add('liquid-chrome',blade(q,width,12,36,.035,.038))

# Eyes are recessed, tapered luminous lenses aligned to the hood's front surface.
# The alternate eyelids are separate geometry so expressions genuinely change shape.
for s in (-1,1):
    tilt=s*.38
    cx=s*.32
    add('eye-open',almond((cx,.18,.635),.15,.25,.032,tilt,10,32))
    add('eye-glint',ellipsoid((cx-s*.026,.245,.671),(.012,.022,.006),10,16))
    add('eye-closed',tube(((s*.51,.18,.666),(s*.43,.105,.676),(s*.31,.105,.676),(s*.24,.18,.666)),.017,8,24,.86,(.55,1.,1.)))
    add('eye-happy',tube(((s*.51,.08,.666),(s*.43,.305,.676),(s*.30,.305,.676),(s*.235,.08,.666)),.022,8,24,.90,(.55,1.,1.)))
    q=((- .51,.33,.666),(-.43,.25,.677),(-.32,.16,.681),(-.24,.16,.666)) if s<0 else ((.24,.16,.666),(.32,.16,.681),(.43,.25,.677),(.51,.33,.666))
    add('eye-angry',tube(q,.026,8,24,.88,(.55,1.,1.)))

MAT={
 'void-shell':{'base':[.004,.005,.008,1.],'metal':.99,'rough':.085,'emit':[.001,.0015,.0025]},
 'liquid-chrome':{'base':[.045,.052,.068,1.],'metal':.98,'rough':.12,'emit':[.004,.005,.008]},
 'eye-open':{'base':[.83,.88,1.,1.],'metal':.1,'rough':.12,'emit':[.52,.62,.92]},
 'eye-glint':{'base':[1.,1.,1.,1.],'metal':0.,'rough':.08,'emit':[.9,.95,1.]},
 'eye-closed':{'base':[.76,.82,1.,1.],'metal':.18,'rough':.15,'emit':[.25,.32,.56]},
 'eye-happy':{'base':[.89,.92,1.,1.],'metal':.12,'rough':.12,'emit':[.5,.62,.98]},
 'eye-angry':{'base':[1.,.22,.27,1.],'metal':.12,'rough':.14,'emit':[.82,.025,.04]},
}

def build_glb()->bytes:
    binary=bytearray();views=[];access=[];primitives=[]
    def align():
        while len(binary)%4:binary.append(0)
    def view(data,target):
        align();off=len(binary);binary.extend(data);views.append({'buffer':0,'byteOffset':off,'byteLength':len(data),'target':target});return len(views)-1
    def accessor(view_id,comp,count,typ,minv=None,maxv=None):
        d={'bufferView':view_id,'componentType':comp,'count':count,'type':typ}
        if minv is not None:d['min']=list(minv)
        if maxv is not None:d['max']=list(maxv)
        access.append(d);return len(access)-1
    for name,meshes in GROUPS.items():
        verts=[];norms=[];indices=[];base=0
        for p,n,f in meshes:
            verts.extend(p);norms.extend(n);indices.extend(tuple(k+base for k in face) for face in f);base+=len(p)
        if len(verts)>65535:raise ValueError(f'{name} exceeds 16-bit index capacity')
        pos=struct.pack('<'+'f'*(len(verts)*3),*(c for v in verts for c in v))
        nor=struct.pack('<'+'f'*(len(norms)*3),*(c for v in norms for c in v))
        ix=struct.pack('<'+'H'*(len(indices)*3),*(c for face in indices for c in face))
        pv=view(pos,34962);nv=view(nor,34962);iv=view(ix,34963)
        pa=accessor(pv,5126,len(verts),'VEC3',[min(v[k] for v in verts) for k in range(3)],[max(v[k] for v in verts) for k in range(3)])
        na=accessor(nv,5126,len(norms),'VEC3');ia=accessor(iv,5123,len(indices)*3,'SCALAR')
        primitives.append({'attributes':{'POSITION':pa,'NORMAL':na},'indices':ia,'material':list(MAT).index(name),'mode':4,'extras':{'materialName':name}})
    materials=[{'name':name,'pbrMetallicRoughness':{'baseColorFactor':m['base'],'metallicFactor':m['metal'],'roughnessFactor':m['rough']},'emissiveFactor':m['emit']} for name,m in MAT.items()]
    gltf={'asset':{'version':'2.0','generator':'Voidling mesh builder'},'scene':0,'scenes':[{'nodes':[0]}],'nodes':[{'name':'Voidling','mesh':0}],'meshes':[{'name':'Voidling-Mesh','primitives':primitives}],'materials':materials,'accessors':access,'bufferViews':views,'buffers':[{'byteLength':len(binary)}]}
    js=json.dumps(gltf,separators=(',',':')).encode()
    while len(js)%4:js+=b' '
    align();total=12+8+len(js)+8+len(binary)
    data=struct.pack('<4sII',b'glTF',2,total)+struct.pack('<II',len(js),0x4E4F534A)+js+struct.pack('<II',len(binary),0x004E4942)+bytes(binary)
    # Header and JSON chunk checks prevent serving a corrupt mesh.
    if data[:4]!=b'glTF' or struct.unpack('<I',data[8:12])[0]!=len(data):raise RuntimeError('Invalid Voidling GLB')
    return data

@lru_cache(maxsize=1)
def get_voidling_glb()->bytes:
    return build_glb()
