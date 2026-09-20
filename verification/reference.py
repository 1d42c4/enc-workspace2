"""Independent file-format cross-checks, not a production encryption tool.

Uses Python hashlib/hmac, PyCryptodome and cryptography/OpenSSL.
Run after cargo build --release --workspace --bins.
"""
from pathlib import Path
import argparse, hashlib, hmac, json, os, shutil, struct, subprocess, tempfile
from Crypto.Cipher import AES, ARC4, ChaCha20, ChaCha20_Poly1305, Salsa20
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
import cryptography

ROOT = Path(__file__).resolve().parents[1]
APPS = json.loads((ROOT/'apps.json').read_text())

def material(a,key,salt):
    digest=hashlib.sha256(key).digest()
    prk=hmac.digest(salt,digest,'sha256')
    info=b'enc-workspace2/v1/keys/'+struct.pack('<H',a['id'])
    n=a['key_len']+a['nonce_len']+32
    expanded=b''; previous=b''
    for i in range(1,(n+31)//32+1):
        previous=hmac.digest(prk,previous+info+bytes([i]),'sha256');expanded+=previous
    expanded=expanded[:n]; k=a['key_len'];iv=k+a['nonce_len']
    return expanded[:k],expanded[k:iv],expanded[iv:]

def toy(name,key,data,decrypt=False):
    mask=(1<<64)-1;state=int.from_bytes(key[:8],'little')|1
    permutation=list(range(256))
    for i in range(255,0,-1):
        state=(state*6364136223846793005+1442695040888963407)&mask
        j=state%(i+1);permutation[i],permutation[j]=permutation[j],permutation[i]
    inverse=[0]*256
    for i,v in enumerate(permutation):inverse[v]=i
    m=key[0]|1;reciprocal=pow(m,-1,256)
    out=[]
    def rotate(x,r):return ((x<<r)|(x>>(8-r)))&255
    for i,b in enumerate(data):
        k=key[i%32]; r=k&7
        if name=='repeating-xor':v=b^k
        elif name=='repeating-add':v=b-k if decrypt else b+k
        elif name=='beaufort-byte':v=k-b
        elif name=='affine-byte':v=(b-key[1])*reciprocal if decrypt else b*m+key[1]
        elif name=='rotate-byte':v=rotate(b,8-r if decrypt and r else r)
        elif name=='xor-rotate':v=rotate(b,8-r if r else 0)^k if decrypt else rotate(b^k,r)
        elif name=='substitution':v=inverse[b] if decrypt else permutation[b]
        elif name=='xorshift64':
            state^=(state<<13)&mask;state^=state>>7;state^=(state<<17)&mask;v=b^(state>>56)
        elif name=='lcg64':
            state=(state*6364136223846793005+1442695040888963407)&mask;v=b^(state>>56)
        else:raise ValueError(name)
        out.append(v&255)
    return bytes(out)

def supported(a):
    n=a['name']
    return n.startswith(('AES-','Toy ','RC4-')) or n in ['ChaCha20Poly1305','XChaCha20Poly1305','ChaCha20-HMAC','XChaCha20-HMAC','Salsa20-HMAC'] or (n.startswith(('CAMELLIA-','SM4-')) and n.endswith(('-CTR','-CBC')))

def body(a,key,nonce,aad,data,decrypt=False):
    n=a['name']
    if n.startswith('Toy '):return toy(a['toy'],key,data,decrypt)
    if n.startswith('RC4-'):return ARC4.new(key).encrypt(data)
    if n in ['ChaCha20-HMAC','XChaCha20-HMAC']:return ChaCha20.new(key=key,nonce=nonce).encrypt(data)
    if n=='Salsa20-HMAC':return Salsa20.new(key=key,nonce=nonce).encrypt(data)
    if n in ['ChaCha20Poly1305','XChaCha20Poly1305']:
        engine=ChaCha20_Poly1305.new(key=key,nonce=nonce);engine.update(aad)
        return engine.decrypt_and_verify(data[:-16],data[-16:]) if decrypt else b''.join(engine.encrypt_and_digest(data))
    if n.endswith('-GCM-SIV'):
        engine=AESGCMSIV(key)
        return engine.decrypt(nonce,data,aad) if decrypt else engine.encrypt(nonce,data,aad)
    if n.startswith('AES-'):
        mode=n.rsplit('-',1)[1]
        if mode in ['GCM','EAX','CCM','SIV']:
            engine=AES.new(key,getattr(AES,'MODE_'+mode),nonce=nonce)
            engine.update(aad)
            if decrypt:
                ct,tag=(data[16:],data[:16]) if mode=='SIV' else (data[:-16],data[-16:])
                return engine.decrypt_and_verify(ct,tag)
            ct,tag=engine.encrypt_and_digest(data)
            return tag+ct if mode=='SIV' else ct+tag
        if mode=='CTR':return AES.new(key,AES.MODE_CTR,nonce=nonce[:-8],initial_value=int.from_bytes(nonce[-8:],'big')).encrypt(data)
        if mode=='CBC':
            engine=AES.new(key,AES.MODE_CBC,iv=nonce)
            return unpad(engine.decrypt(data),16) if decrypt else engine.encrypt(pad(data,16))
    primitive=Camellia(key) if n.startswith('CAMELLIA-') else algorithms.SM4(key)
    if n.endswith('-CTR'):
        # Independent CTR64BE over OpenSSL ECB, including the final-64-bit wrap rule.
        engine=Cipher(primitive,modes.ECB()).encryptor()
        initial=int.from_bytes(nonce[-8:],'big');out=bytearray()
        for block_index,start in enumerate(range(0,len(data),16)):
            counter=nonce[:-8]+((initial+block_index)&((1<<64)-1)).to_bytes(8,'big')
            stream=engine.update(counter)
            out.extend(x^y for x,y in zip(data[start:start+16],stream))
        assert engine.finalize()==b''
        return bytes(out)
    mode=modes.CBC(nonce)
    engine=Cipher(primitive,mode).decryptor() if decrypt else Cipher(primitive,mode).encryptor()
    padded=pad(data,16) if not decrypt and n.endswith('-CBC') else data
    out=engine.update(padded)+engine.finalize()
    return unpad(out,16) if decrypt and n.endswith('-CBC') else out

def unpack(a,key,encoded):
    header=encoded[:64];cipher_key,nonce,mac_key=material(a,key,header[20:52])
    assert hmac.compare_digest(hmac.digest(mac_key,encoded[:-32],'sha256'),encoded[-32:])
    return body(a,cipher_key,nonce,header,encoded[64:-32],True)

def pack(a,key,plain):
    header=b'ENCWS2\r\n'+b'\x01'+struct.pack('<H',a['id'])+b'\0'+struct.pack('<Q',len(plain))+os.urandom(32)+bytes(12)
    cipher_key,nonce,mac_key=material(a,key,header[20:52])
    encoded=header+body(a,cipher_key,nonce,header,plain)
    return encoded+hmac.digest(mac_key,encoded,'sha256')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bin-dir',type=Path,default=ROOT/'target/release');args=parser.parse_args()
    report=[]
    for a in APPS:
        if not supported(a):continue
        with tempfile.TemporaryDirectory(prefix='encws2-reference-') as d:
            folder=Path(d);name=a['app']+('.exe' if os.name=='nt' else '')
            exe=folder/name;shutil.copy2(args.bin_dir/name,exe)
            key=os.urandom(43);(folder/'key.key').write_bytes(key)
            for n in [0,1,15,16,17,257,4097]:
                plain=bytes((i*137+i//256)&255 for i in range(n));(folder/'plain').write_bytes(plain)
                subprocess.run([str(exe),'E','plain','rust'],cwd=ROOT,check=True,capture_output=True)
                assert unpack(a,key,(folder/'rust').read_bytes())==plain,(a['app'],'Rust -> reference',n)
                (folder/'reference').write_bytes(pack(a,key,plain))
                subprocess.run([str(exe),'D','reference','restored'],cwd=ROOT,check=True,capture_output=True)
                assert (folder/'restored').read_bytes()==plain,(a['app'],'reference -> Rust',n)
                for output in ['rust','reference','restored']:(folder/output).unlink()
        report.append({'app':a['app'],'algorithm':a['name'],'directional_checks':14})
        print(a['app'],a['name'],'14 checks passed',flush=True)
    result={'implementations':['Python hashlib/hmac','PyCryptodome 3.23.0',f'cryptography {cryptography.__version__}/OpenSSL (CTR64BE composed independently over ECB)'],'apps_checked':len(report),'directional_checks':sum(r['directional_checks'] for r in report),'results':report,'limitations':'Other algorithms are covered by Rust roundtrip/adversarial/CLI tests and published primitive vectors; no claim of independent interoperability for every app. Toy references are independent Python transcriptions, not external cryptographic validation.'}
    (ROOT/'verification/independent-results.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='results'},indent=2))

if __name__=='__main__':main()
