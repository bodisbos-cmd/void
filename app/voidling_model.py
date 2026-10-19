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

def almond(center,rx,ry,depth,tilt=0.,rings=7,sides=24):
    p=[];n=[];f=[]
    for back in (False,True):
        for ir in range(rings+1):
            r=ir/rings
            for j in range(sides):
                t=2*math.pi*j/sides;sy=math.sin(t);x=rx*r*math.cos(t);y=ry*r*sy*(abs(sy)**.18)
                z=(-.20 if back else 1.)*depth*math.sqrt(max(0.,1-r*r))
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

# Main dark-chrome shell, smaller torso, and organic shoulder connector.
add('void-shell',ellipsoid((-.015,.27,0),(.82,.80,.655),28,44,True))
add('void-shell',ellipsoid((0,-.57,.025),(.30,.39,.265),18,28,True))
add('void-shell',ellipsoid((0,-.315,.015),(.205,.18,.19),16,24))
for s in (-1,1):
    add('liquid-chrome',tube(((s*.48,.28,.12),(s*.88,.53,.19),(s*.63,.99,.12),(s*.18,1.15,.05)),.105,10,26,.10))
    add('liquid-chrome',tube(((s*.59,.03,.16),(s*.96,.32,.20),(s*.67,.69,.16),(s*.25,.67,.23)),.068,9,24,.12))
    add('liquid-chrome',tube(((s*.35,-.36,.05),(s*.73,-.60,.16),(s*.47,-.93,.20),(s*.18,-1.12,.10)),.067,9,24,.08))
# Broad swept shell blades are actual curved surfaces, not thin tubes or painted effects.
add('liquid-chrome',blade(((-.58,.29,.39),(-.98,.52,.32),(-.78,.94,.20),(-.39,1.13,.12)),.145,9,30,.045,.022))
add('liquid-chrome',blade(((-.43,.55,.21),(-.55,1.09,.09),(-.06,1.36,.015),(.35,1.05,.12)),.105,9,30,.05,.020))
add('liquid-chrome',blade(((.54,.27,.29),(.94,.51,.18),(.89,.94,.07),(.57,1.13,.045)),.105,8,28,.045,.020))
add('liquid-chrome',blade(((-.69,.08,.40),(-.94,.28,.36),(-.86,.60,.28),(-.58,.79,.31)),.112,8,25,.06,.019))
add('liquid-chrome',blade(((.58,.03,.38),(.82,.28,.32),(.78,.52,.25),(.57,.68,.27)),.085,8,24,.06,.017))
tails=[
 ((-.19,-.69,.04),(-.52,-.91,.22),(-.27,-1.25,.16),(-.61,-1.47,.04)),
 ((-.055,-.72,.11),(-.19,-1.03,.24),(.14,-1.22,.14),(.08,-1.48,.07)),
 ((.12,-.70,.01),(.47,-.91,-.04),(.23,-1.24,.02),(.55,-1.44,.03)),
 ((.27,-.64,-.055),(.62,-.85,-.16),(.62,-1.16,-.035),(.84,-1.35,-.015)),
 ((-.29,-.62,-.04),(-.64,-.81,-.14),(-.57,-1.10,-.015),(-.79,-1.34,.005)),
 ((.015,-.79,-.12),(.28,-1.01,-.25),(-.08,-1.25,-.14),(-.22,-1.45,-.055)),
]
for i,q in enumerate(tails):add('liquid-chrome',tube(q,.079 if i in (1,5) else .067,8,24,.035))
# Fine pointed blades underlay the rounded filaments to create the layered liquid-metal silhouette.
for i,q in enumerate(tails):
    if i in (0,1,2,3,4):
        add('liquid-chrome',blade(q,.083 if i in (1,2,4) else .071,7,27,.025,.020))
add('liquid-chrome',blade(((-.32,-.49,.15),(-.69,-.69,.27),(-.46,-.99,.19),(-.30,-1.28,.10)),.091,7,25,.035,.021))
add('liquid-chrome',blade(((.29,-.48,.15),(.59,-.72,.23),(.52,-.99,.11),(.69,-1.23,.055)),.082,7,25,.035,.019))
for s in (-1,1):
    add('liquid-chrome',tube(((s*.27,-.39,.10),(s*.56,-.34,.32),(s*.64,-.55,.29),(s*.42,-.73,.18)),.048,8,22,.1,(.50,1.,1.)))
# State-specific eye meshes keep the five faces as actual geometry in the model.
for s in (-1,1):
    tilt=-s*.15
    add('eye-open',almond((s*.295,.205,.558),.205,.278,.060,tilt))
    add('eye-glint',ellipsoid((s*.295-s*.045,.286,.620),(.026,.044,.014),8,12))
    add('eye-closed',tube(((s*.48,.18,.57),(s*.42,.12,.59),(s*.32,.12,.60),(s*.25,.18,.57)),.022,7,20,.85,(.65,1.,1.)))
    add('eye-happy',tube(((s*.49,.105,.57),(s*.43,.31,.60),(s*.32,.31,.61),(s*.245,.105,.57)),.027,7,20,.90,(.65,1.,1.)))
    q=((- .49,.35,.56),(-.42,.28,.60),(-.32,.17,.61),(-.245,.17,.57)) if s<0 else ((.245,.17,.57),(.32,.17,.61),(.42,.28,.60),(.49,.35,.56))
    add('eye-angry',tube(q,.031,7,20,.90,(.65,1.,1.)))

MAT={
 'void-shell':{'base':[.009,.012,.020,1.],'metal':.98,'rough':.105,'emit':[.002,.003,.007]},
 'liquid-chrome':{'base':[.040,.050,.077,1.],'metal':.96,'rough':.155,'emit':[.006,.010,.020]},
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
