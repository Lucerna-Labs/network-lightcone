#!/usr/bin/env python3
"""Fresh covered-wire fixtures and frozen expected seeds, independent of runtime."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import struct

V4={'ipv4','ip_header','ip_length','ip_checksum','ip_protocol','endpoint_addresses','ip_ttl'}
V6={'ipv6','ipv6_payload_length','ipv6_next_header','ipv6_hop_limit','ipv6_source','ipv6_destination'}
UDP={'udp','udp_length','udp_ports'}
TCP={'tcp','tcp_ports','tcp_checksum'}
ICMP6={'icmpv6','icmpv6_checksum'}
AUTH={'authenticated_peer','authorized_flow','policy_decision','dns_query','tls','http','ssh'}


def checksum(data):
    data+=b'\0'*(len(data)%2)
    total=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


class Frames:
    def __init__(self,variant):
        self.v=variant;self.s4=ipaddress.ip_address(f'198.51.100.{10+variant}').packed
        self.d4=ipaddress.ip_address(f'198.51.100.{40+variant}').packed
        self.s6=ipaddress.ip_address(f'fe80::{10+variant:x}').packed
        self.d6=ipaddress.ip_address(f'fe80::{40+variant:x}').packed
        self.payload=[b'',b'covered-payload',b'node=authorized_flow; dns_query; policy_decision'][variant]
    def ethernet(self,kind,data):return bytes.fromhex('020000000021020000000022')+struct.pack('!H',kind)+data
    def ip4(self,data,protocol,fragment=0,options=b'',length=None,bad_checksum=False):
        h=bytearray(20+len(options));h[0]=0x40+len(h)//4;h[2:4]=struct.pack('!H',length or len(h)+len(data))
        h[6:8]=struct.pack('!H',fragment);h[8]=[1,64,255][self.v];h[9]=protocol
        h[12:16]=self.s4;h[16:20]=self.d4;h[20:]=options;h[10:12]=struct.pack('!H',checksum(bytes(h)))
        if bad_checksum:h[10]^=1
        return self.ethernet(0x800,bytes(h)+data)
    def ip6(self,data,protocol,hop=64,source=None,destination=None):
        source=source or self.s6;destination=destination or self.d6
        h=struct.pack('!IHBB',6<<28,len(data),protocol,hop)+source+destination
        return self.ethernet(0x86dd,h+data)
    def transport(self,data,protocol,version,offset,corrupt=False,source=None,destination=None):
        data=bytearray(data)
        pseudo=(self.s4+self.d4+b'\0'+bytes([protocol])+struct.pack('!H',len(data))) if version==4 else (
            (source or self.s6)+(destination or self.d6)+struct.pack('!I',len(data))+b'\0\0\0'+bytes([protocol]))
        value=checksum(pseudo+data)
        data[offset:offset+2]=struct.pack('!H',value or 65535)
        if corrupt:data[offset]^=1
        return bytes(data)
    def udp(self,version,present=True,source_port=None,length=None,corrupt=False,extensions=()):
        sport=21000+self.v if source_port is None else source_port
        d=struct.pack('!HHHH',sport,31000+self.v,length if length is not None else 8+len(self.payload),0)+self.payload
        if present:d=self.transport(d,17,version,6,corrupt)
        if version==4:return self.ip4(d,17)
        next_header=17
        for kind in reversed(extensions):d=bytes([next_header,0])+bytes(6)+d;next_header=kind
        return self.ip6(d,next_header)
    def tcp(self,version,flags,payload=False,header=5,corrupt=False):
        d=struct.pack('!HHIIBBHHH',22000+self.v,32000+self.v,12345+self.v,9876,header<<4,flags,8192,0,0)
        d+=b'ordinary-data' if payload else b''
        d=self.transport(d,6,version,16,corrupt)
        return self.ip4(d,6) if version==4 else self.ip6(d,6)
    def icmp4(self,kind,code=0,corrupt=False):
        d=bytearray(bytes([kind,code,0,0])+bytes(4)+self.payload)
        d[2:4]=struct.pack('!H',checksum(bytes(d)))
        if corrupt:d[2]^=1
        return self.ip4(bytes(d),1)
    def icmp6(self,kind,code=0,hop=255,corrupt=False,source=None,destination=None,target=None,option=b''):
        length=16 if kind==134 else 24 if kind in (135,136) else 8
        d=bytearray(length);d[0]=kind;d[1]=code
        if kind in (135,136):d[8:24]=target or self.d6
        d+=option
        d=self.transport(d,58,6,2,corrupt,source,destination)
        return self.ip6(d,58,hop,source,destination)
    def arp(self,operation):
        d=struct.pack('!HHBBH',1,0x800,6,4,operation)+bytes.fromhex('020000000022')+self.s4+bytes(6)+self.d4
        return self.ethernet(0x806,d)


def build(variant):
    f=Frames(variant);cases=[]
    def add(name,frame,seeds,kind='decoded',reason=None,relations=(),scope_edges=(),pair=None):
        cases.append({'id':f'v{variant}-{name}','family':name,'variant':variant,'frame':frame,
                      'expected_seeds':sorted(seeds),'expected_kind':kind,'expected_reason':reason,
                      'required_relations':list(relations),'forbidden_unqualified_edges':list(scope_edges),
                      'forbidden_direct_seeds':sorted(AUTH),'pair':pair})
    add('arp-request',f.arp(1),{'arp_request'},reason='arp_request_valid',relations=['e000','e004'])
    add('arp-reply',f.arp(2),{'arp_reply'},reason='arp_reply_valid',relations=['e001','e002'])
    add('udp4-zero',f.udp(4,False),V4|UDP|{'udp_no_checksum'},reason='ipv4_udp_no_checksum',relations=['e020','e021'])
    add('udp4-checksum',f.udp(4),V4|UDP|{'udp_checksum','udp_integrity'},reason='ipv4_udp_valid',relations=['e018','e062','e021'])
    add('udp4-source-zero',f.udp(4,False,source_port=0),V4|UDP|{'udp_no_checksum','udp_source_zero'},reason='ipv4_udp_no_checksum')
    plain=f.udp(4,False);add('ipv4-options',f.ip4(plain[34:],17,options=b'\x01\x01\0\0'),V4|UDP|{'udp_no_checksum'},reason='ipv4_udp_no_checksum')
    for name,ext in [('udp6',()),('udp6-hbh',(0,)),('udp6-chain',(0,60))]:
        add(name,f.udp(6,extensions=ext),V6|UDP|{'udp_checksum','udp_integrity'}|({'ipv6_extension'} if ext else set()),
            reason='ipv6_udp_valid',relations=['e018','e021'],scope_edges=['e014','e019'])
    for version,base in [(4,V4),(6,V6)]:
        for name,flags,symbols,data,relations in [
            ('syn',2,{'tcp_syn'},False,['e032','e034','e038','e186']),
            ('syn-ack',18,{'tcp_syn','tcp_ack'},False,['e034','e035']),
            ('ack-data',24,{'tcp_ack','tcp_payload'},True,['e032','e035','e186']),
            ('fin-ack',17,{'tcp_fin','tcp_ack'},False,['e036']),
            ('rst',4,{'tcp_rst'},False,['e037'])]:
            add(f'tcp{version}-{name}',f.tcp(version,flags,data),base|TCP|symbols,reason=f'ipv{version}_tcp_valid',
                relations=relations,scope_edges=['e039'] if version==6 else [])
    for name,kind,node,relations in [('echo-request',8,'icmp_request',['e025','e027']),('echo-reply',0,'icmp_reply',['e026','e028']),
                                    ('unreachable',3,'icmp_unreachable',['e054']),('expired',11,'icmp_expired',['e055'])]:
        add('icmp4-'+name,f.icmp4(kind),V4|{'icmp_checksum',node},reason='icmpv4_valid',relations=relations)
    add('icmp6-error',f.icmp6(1,hop=64),V6|ICMP6|{'icmpv6_error'},reason='icmpv6_valid',relations=['e073'])
    add('icmp6-info',f.icmp6(128,hop=64),V6|ICMP6,reason='icmpv6_unrepresented_type',relations=['e073'])
    for kind,node,relations in [(133,'router_solicitation',['e075']),(134,'router_advertisement',['e075']),
                               (135,'neighbor_solicitation',['e076','e080']),(136,'neighbor_advertisement',['e077'])]:
        add('ndp-'+str(kind),f.icmp6(kind),V6|ICMP6|{'ndp',node},reason='icmpv6_valid',relations=relations)
    add('ipv4-fragment',f.ip4(bytes(16),17,fragment=0x2000),V4|{'ip_fragment'},kind='fragment',reason='ipv4_fragment_requires_reassembly',relations=['e011'])
    add('ipv6-fragment',f.ip6(bytes([17,0,0,1])+bytes(12),44),V6|{'ipv6_fragment'},kind='fragment',reason='ipv6_fragment_requires_reassembly',relations=['e070'])
    add('ipv4-header-only',f.ip4(bytes(8),253),V4,reason='ipv4_header_only_unrepresented_transport')
    add('ipv6-header-only',f.ip6(bytes(8),253),V6,reason='ipv6_header_only_unrepresented_transport')
    negatives=[
        ('ip4-checksum',f.ip4(bytes(8),17,bad_checksum=True),'ipv4_bad_header_checksum'),
        ('ip4-length',f.ip4(bytes(8),17,length=500),'ipv4_total_length_invalid'),
        ('udp4-length',f.udp(4,False,length=7),'udp_length_mismatch'),
        ('udp4-checksum',f.udp(4,corrupt=True),'udp_ipv4_bad_checksum'),
        ('udp6-zero',f.udp(6,False),'udp_ipv6_zero_checksum'),
        ('udp6-checksum',f.udp(6,corrupt=True),'udp_ipv6_bad_checksum'),
        ('tcp4-header',f.tcp(4,2,header=4),'tcp_header_length_invalid'),
        ('tcp4-checksum',f.tcp(4,2,corrupt=True),'tcp_bad_checksum'),
        ('tcp6-checksum',f.tcp(6,2,corrupt=True),'tcp_bad_checksum'),
        ('icmp4-checksum',f.icmp4(8,corrupt=True),'icmpv4_bad_checksum'),
        ('icmp6-checksum',f.icmp6(135,corrupt=True),'icmpv6_bad_checksum'),
        ('ndp-hop',f.icmp6(135,hop=64),'ndp_hop_limit_invalid'),
        ('ndp-code',f.icmp6(135,code=1),'ndp_code_invalid'),
        ('ndp-ra-source',f.icmp6(134,source=ipaddress.ip_address('2001:db8::1').packed),'ndp_router_source_not_link_local'),
        ('ndp-target',f.icmp6(135,target=ipaddress.ip_address('ff02::1').packed),'ndp_multicast_target'),
        ('ndp-option',f.icmp6(135,option=b'\x01\0'),'ndp_option_length_invalid'),
        ('extension-length',f.ip6(bytes([17,1])+bytes(6),0),'ipv6_extension_length_invalid'),
        ('hbh-order',f.udp(6,extensions=(60,0)),'ipv6_hop_by_hop_not_first'),
        ('short-ethernet',b'\x00'*7,'ethernet_short_frame')]
    for name,frame,reason in negatives:add('invalid-'+name,frame,set(),'malformed',reason)
    add('unknown-ether',f.ethernet(0x88b5,f.payload),set(),'unknown','ethernet_unrepresented_ethertype')
    add('unknown-arp-operation',f.arp(3),set(),'unknown','arp_unrepresented_operation')
    return cases


def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    all_cases=[]
    for variant in range(3):
        rows=build(variant);pcap=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
        for i,row in enumerate(rows):
            frame=row.pop('frame');pcap+=struct.pack('<IIII',100+variant,i,len(frame),len(frame))+frame
            row['frame_sha256']=hashlib.sha256(frame).hexdigest();row['frame_bytes']=len(frame);row['sequence']=i+1
        path=a.out/f'variant-{variant}.pcap';path.write_bytes(pcap)
        all_cases+=rows
    result={'status':'frozen_before_replay','cases':all_cases,'case_count':len(all_cases),
            'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'inputs':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(a.out.glob('*.pcap'))},
            'source_refs':['RFC768','RFC791','RFC792','RFC826','RFC4443','RFC4861','RFC8200','RFC9293'],
            'exclusions':['DNS semantic decoding','VLAN','NDP option-content semantics','TCP connection-state enforcement','payload/identity/authorization decisions'],
            'scope':'fresh structural fixtures and scoped evidence retrieval; no training inputs or transmitted attacks'}
    (a.out/'manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'cases':len(all_cases),'per_variant':len(all_cases)//3,'manifest_sha256':hashlib.sha256((a.out/'manifest.json').read_bytes()).hexdigest()}))


if __name__=='__main__':main()
