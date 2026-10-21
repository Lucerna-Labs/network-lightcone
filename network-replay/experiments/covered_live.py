#!/usr/bin/env python3
"""Covered TCP/UDP/ICMP traffic on private veth peers with TX offload disabled."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import threading
import time

A4,B4='10.207.41.1','10.207.41.2'
A6,B6='fd42:207:41::1','fd42:207:41::2'
PORT=51241


def cmd(*args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def payload(family,kind):return f'C01-{family}-{kind}|'.encode()+bytes(range(64))


def server(out):
    listeners=[];rows=[];threads=[]
    for family,address in [(socket.AF_INET,B4),(socket.AF_INET6,B6)]:
        for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
            s=socket.socket(family,kind);s.settimeout(12)
            if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            s.bind((address,PORT))
            if kind==socket.SOCK_STREAM:s.listen(1)
            listeners.append((s,family,kind))
    def serve(s,family,kind):
        record={'family':family,'kind':kind}
        try:
            expected=payload(family,kind)
            if kind==socket.SOCK_STREAM:
                peer,_=s.accept();peer.settimeout(5)
                with peer:
                    data=b''
                    while len(data)<len(expected):
                        part=peer.recv(4096)
                        if not part:break
                        data+=part
                    peer.sendall(data)
            else:
                data,address=s.recvfrom(4096);s.sendto(data,address)
            record.update(passed=data==expected,received_bytes=len(data),payload_sha256=hashlib.sha256(data).hexdigest())
        except Exception as e:record.update(passed=False,error=str(e))
        finally:s.close();rows.append(record)
    for s,f,k in listeners:
        t=threading.Thread(target=serve,args=(s,f,k),daemon=True);t.start();threads.append(t)
    print('READY',flush=True)
    for t in threads:t.join(timeout=15)
    (out/'server.json').write_text(json.dumps(rows,indent=2)+'\n')
    return 0 if len(rows)==4 and all(r['passed'] for r in rows) else 1


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--server',action='store_true');a=p.parse_args()
    out=a.out.resolve()
    if a.server:return server(out)
    uid=Path('/proc/self/uid_map').read_text().split()
    if os.geteuid()!=0 or len(uid)!=3 or uid[0]!='0' or uid[2]!='1' or sorted(n for _,n in socket.if_nameindex())!=['lo']:
        raise RuntimeError('Only run inside unshare -Urn with an empty private network namespace')
    out.mkdir(parents=True,exist_ok=False)
    (out/'plan.json').write_text(json.dumps({'status':'frozen_before_transmission','script_sha256':sha(Path(__file__)),
        'addresses':[A4,B4,A6,B6],'port':PORT,'exchanges':['IPv4 TCP echo','IPv4 UDP echo','IPv6 TCP echo','IPv6 UDP echo','IPv4 ICMP echo','IPv6 ICMP echo'],
        'expectations':['all exact byte echoes and pings succeed','TX checksumming off on both private interfaces','zero capture drops','no malformed covered live frames'],
        'scope':'only private network namespaces; no host interface changes'},indent=2)+'\n')
    holder=service=capture=None
    try:
        holder=subprocess.Popen(['unshare','-n','sleep','60']);time.sleep(.2)
        if holder.poll() is not None:raise RuntimeError('server namespace exited')
        prefix=['nsenter','-t',str(holder.pid),'-n','--preserve-credentials']
        cmd('ip','link','add','vethcov0','type','veth','peer','name','vethcov1')
        cmd('ip','link','set','vethcov1','netns',str(holder.pid))
        cmd('ip','addr','add',A4+'/24','dev','vethcov0');cmd('ip','-6','addr','add',A6+'/64','dev','vethcov0','nodad')
        cmd('ip','link','set','vethcov0','up');cmd('ip','link','set','lo','up')
        cmd(*prefix,'ip','addr','add',B4+'/24','dev','vethcov1');cmd(*prefix,'ip','-6','addr','add',B6+'/64','dev','vethcov1','nodad')
        cmd(*prefix,'ip','link','set','vethcov1','up');cmd(*prefix,'ip','link','set','lo','up')
        cmd('ethtool','-K','vethcov0','tx','off');cmd(*prefix,'ethtool','-K','vethcov1','tx','off')
        settings={'client':cmd('ethtool','-k','vethcov0'),'server':cmd(*prefix,'ethtool','-k','vethcov1')}
        (out/'offload-settings.json').write_text(json.dumps(settings,indent=2)+'\n')
        if not all('tx-checksumming: off' in s for s in settings.values()):raise RuntimeError('TX checksumming remains enabled')
        service=subprocess.Popen(prefix+['python3',str(Path(__file__).resolve()),'--server','--out',str(out)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if service.stdout.readline().strip()!='READY':raise RuntimeError('server not ready')
        capture=subprocess.Popen(['tcpdump','-i','vethcov0','-U','-s','0','-nn','-Z','root','-w',str(out/'capture.pcap')],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        time.sleep(.4)
        if capture.poll() is not None:raise RuntimeError('capture exited')
        rows=[]
        for family,address in [(socket.AF_INET,B4),(socket.AF_INET6,B6)]:
            for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
                with socket.socket(family,kind) as peer:
                    peer.settimeout(5);peer.connect((address,PORT));data=payload(family,kind)
                    peer.sendall(data);received=b''
                    while len(received)<len(data):
                        part=peer.recv(4096)
                        if not part:break
                        received+=part
                rows.append({'family':family,'kind':kind,'passed':received==data,'bytes':len(received)})
        ping4=cmd('ping','-4','-c','1','-W','3',B4);ping6=cmd('ping','-6','-c','1','-W','3',B6)
        (out/'ping4.txt').write_text(ping4);(out/'ping6.txt').write_text(ping6)
        _,stderr=service.communicate(timeout=10)
        if service.returncode:raise RuntimeError('server failed: '+stderr)
        time.sleep(2.)
        try:capture.send_signal(signal.SIGINT)
        except PermissionError:cmd('aa-exec','-p','tcpdump','--','kill','-INT',str(capture.pid))
        _,capture_stderr=capture.communicate(timeout=5)
        if capture.returncode:raise RuntimeError('capture failed: '+capture_stderr)
        result={'status':'captured','application_exchanges':rows,'ping4_pass':True,'ping6_pass':True,
                'server':json.loads((out/'server.json').read_text()),'capture_stderr':capture_stderr,
                'pcap_sha256':sha(out/'capture.pcap'),'pcap_bytes':(out/'capture.pcap').stat().st_size,
                'offload_settings_sha256':sha(out/'offload-settings.json')}
        (out/'capture.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
        return 0 if all(r['passed'] for r in rows) else 1
    except Exception as error:
        (out/'failure.json').write_text(json.dumps({'error':str(error)},indent=2)+'\n');raise
    finally:
        if capture and capture.poll() is None:
            try:capture.send_signal(signal.SIGINT)
            except PermissionError:subprocess.run(['aa-exec','-p','tcpdump','--','kill','-INT',str(capture.pid)],check=False)
            try:capture.wait(timeout=5)
            except subprocess.TimeoutExpired:capture.kill()
        for process in [service,holder]:
            if process and process.poll() is None:process.terminate();process.wait(timeout=5)


if __name__=='__main__':raise SystemExit(main())
