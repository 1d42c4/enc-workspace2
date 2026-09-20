"""Run every release executable with a fresh disposable key and binary input."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, tempfile

ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--bin-dir',type=Path,default=ROOT/'target/release');args=p.parse_args()
    suffix='.exe' if os.name=='nt' else ''
    generator=(args.bin_dir/('keygen'+suffix)).resolve()
    apps=json.loads((ROOT/'apps.json').read_text());results=[]
    plain=bytes((i*103+i//257)&255 for i in range(4099))
    for a in apps:
        source=(args.bin_dir/(a['app']+suffix)).resolve()
        with tempfile.TemporaryDirectory(prefix='encws2-release-') as temp:
            folder=Path(temp);exe=folder/source.name;shutil.copy2(source,exe)
            subprocess.run([str(generator),str(folder)],check=True,capture_output=True)
            assert len((folder/'key.key').read_bytes())==32
            (folder/'input').write_bytes(plain)
            for mode,src,dst in [('E','input','sealed'),('D','sealed','restored')]:
                subprocess.run([str(exe),mode,src,dst],cwd=ROOT,check=True,capture_output=True)
            assert (folder/'restored').read_bytes()==plain
            assert (folder/'input').read_bytes()==plain
            corrupted=bytearray((folder/'sealed').read_bytes());corrupted[-1]^=1;(folder/'bad').write_bytes(corrupted)
            rejected=subprocess.run([str(exe),'D','bad','must-not-exist'],cwd=ROOT,capture_output=True)
            assert rejected.returncode!=0 and not (folder/'must-not-exist').exists()
        results.append({'app':a['app'],'name':a['name'],'sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'checks':['key generation','encrypt','decrypt','tamper rejection without output']})
    report={'apps_passed':len(results),'executable_invocations':len(results)*4,'results':results}
    (ROOT/'verification/release-smoke.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f'{len(results)} release apps passed; {len(results)*4} executable invocations')
if __name__=='__main__':main()
