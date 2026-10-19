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

# Main silhouette: broad, slightly flattened black-chrome head and a small tucked torso.
add('void-shell',ellipsoid((-.015,.27,0),(.86,.76,.655),30,48,True))
add('void-shell',ellipsoid((0,-.56,.015),(.275,.345,.255),20,32,True))
add('void-shell',ellipsoid((0,-.34,.055),(.185,.18,.19),16,24))

# Two quiet, rear-offset filaments give the torso depth without creating a tangled wire bundle.
add('liquid-chrome',tube(((-.22,-.39,-.08),(-.50,-.47,-.23),(-.46,-.68,-.30),(-.28,-.83,-.22)),.034,8,26,.10))
add('liquid-chrome',tube(((.22,-.38,-.08),(.51,-.47,-.23),(.44,-.69,-.30),(.28,-.84,-.22)),.032,8,26,.10))

# Crown and cheek fins: swept leaf-shaped surfaces that emerge from the shell,
# with distinct front/back depth instead of round loops sitting on top of the head.
add('liquid-chrome',blade(((-.54,.25,.57),(-.98,.34,.54),(-.91,.78,.33),(-.43,1.04,.12)),.185,10,32,.035,.028))
add('liquid-chrome',blade(((-.43,.55,.61),(-.30,1.04,.56),(.15,1.17,.13),(.40,.86,.20)),.145,10,32,.035,.024))
add('liquid-chrome',blade(((.51,.27,.57),(.99,.45,.48),(.88,.84,.25),(.56,1.00,.10)),.155,9,30,.035,.025))
add('liquid-chrome',blade(((-.66,.05,.49),(-.91,.31,.48),(-.82,.57,.35),(-.58,.73,.30)),.105,8,26,.05,.022))
# Rear-side fins remain visible when rotated to profile or back view.
add('liquid-chrome',blade(((-.48,.22,-.36),(-.79,.48,-.43),(-.70,.79,-.38),(-.36,.91,-.20)),.13,8,28,.04,.022))
add('liquid-chrome',blade(((.48,.22,-.36),(.78,.48,-.43),(.69,.78,-.38),(.36,.91,-.20)),.12,8,28,.04,.022))

# Four broad liquid-metal tail ribbons form a clean layered silhouette beneath the torso.
tails=[
 ((-.18,-.53,.26),(-.57,-.72,.43),(-.38,-1.06,.27),(-.78,-1.36,.015)),
 ((-.09,-.59,.32),(-.31,-.82,.45),(-.08,-1.12,.22),(-.22,-1.43,.035)),
 ((.10,-.58,.31),(.42,-.78,.44),(.20,-1.10,.20),(.55,-1.38,.02)),
 ((.25,-.52,.22),(.65,-.72,.34),(.52,-1.00,.12),(.80,-1.32,-.02)),
]
for q,width in zip(tails,(.145,.125,.137,.132)):
    add('liquid-chrome',blade(q,width,9,30,.025,.026))
# One fine edge filament trails behind the right fin, keeping the reference's delicate tendril detail.
add('liquid-chrome',tube(((.23,-.62,-.17),(.49,-.88,-.31),(.12,-1.18,-.25),(.25,-1.45,-.08)),.027,7,26,.06))

# Large, angled almond lenses sit in front of the shell. Alternate eyelid meshes
# are separate real geometry used by the online/checking/error/sleep/response states.
for s in (-1,1):
    tilt=s*.49
    add('eye-open',almond((s*.315,.17,.755),.192,.245,.078,tilt))
    add('eye-glint',ellipsoid((s*.315-s*.045,.238,.833),(.021,.034,.012),8,12))
    add('eye-closed',tube(((s*.48,.17,.78),(s*.42,.115,.80),(s*.32,.115,.81),(s*.25,.17,.78)),.024,8,22,.82,(.65,1.,1.)))
    add('eye-happy',tube(((s*.49,.10,.78),(s*.43,.30,.81),(s*.32,.30,.82),(s*.245,.10,.78)),.028,8,22,.88,(.65,1.,1.)))
    q=((- .49,.34,.77),(-.42,.27,.81),(-.32,.16,.82),(-.245,.16,.78)) if s<0 else ((.245,.16,.78),(.32,.16,.82),(.42,.27,.81),(.49,.34,.77))
    add('eye-angry',tube(q,.033,8,22,.86,(.65,1.,1.)))

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
