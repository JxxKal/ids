import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { createPortal } from 'react-dom';
import { getToken, pcapUrl } from '../api';

// ─── Types ────────────────────────────────────────────────────────────────────

interface PcapPacket {
  num: number;
  tsSec: number;
  tsUsec: number;
  capLen: number;
  origLen: number;
  proto: string;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  tcpFlags: number;
  icmpType: number | null;
  icmpCode: number | null;
  info: string;
  raw: Uint8Array;
  linkType: number;   // pcap link-layer type (1=Ethernet, …) — für den Layer-Decoder
}

// ─── PCAP Parser ──────────────────────────────────────────────────────────────

function r16be(a: Uint8Array, o: number) { return (a[o] << 8) | a[o + 1]; }
function r32le(a: Uint8Array, o: number) { return (a[o] | (a[o+1]<<8) | (a[o+2]<<16) | (a[o+3]<<24)) >>> 0; }
function r32be(a: Uint8Array, o: number) { return ((a[o]<<24) | (a[o+1]<<16) | (a[o+2]<<8) | a[o+3]) >>> 0; }

function ipv4Str(a: Uint8Array, o: number) { return `${a[o]}.${a[o+1]}.${a[o+2]}.${a[o+3]}`; }

function ipv6Str(a: Uint8Array, o: number): string {
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(r16be(a, o + i).toString(16));
  let bs = -1, bl = 0, cs = -1, cl = 0;
  for (let i = 0; i < 8; i++) {
    if (g[i] === '0') { if (cs < 0) cs = i; cl++; if (cl > bl) { bl = cl; bs = cs; } }
    else { cs = -1; cl = 0; }
  }
  if (bl >= 2) {
    const pre = g.slice(0, bs).join(':');
    const suf = g.slice(bs + bl).join(':');
    // pre/suf sind bei einem Zero-Run am Anfang bzw. Ende leer — das "::" aus
    // dem Template liefert dann bereits die korrekte Kurzform (z.B. "::1",
    // "1::", "::"). Kein Trimmen von führendem/abschließendem ":", sonst
    // wird "::1" fälschlich zu ":1".
    return `${pre}::${suf}`;
  }
  return g.join(':');
}

const TCP_FLAG_NAMES = ['FIN','SYN','RST','PSH','ACK','URG'];
function tcpFlagsStr(f: number) { return TCP_FLAG_NAMES.filter((_,i) => f & (1<<i)).join(',') || '.'; }

const ICMP4: Record<number,string> = { 0:'Echo Reply', 3:'Dest Unreachable', 5:'Redirect', 8:'Echo Request', 11:'TTL Exceeded', 12:'Param Problem' };
const ICMP6: Record<number,string> = { 1:'Dest Unreachable', 2:'Packet Too Big', 3:'TTL Exceeded', 128:'Echo Request', 129:'Echo Reply', 133:'Router Solicitation', 134:'Router Advertisement', 135:'Neighbor Solicitation', 136:'Neighbor Advertisement' };

function mkBase(num: number, tsSec: number, tsUsec: number, capLen: number, origLen: number, raw: Uint8Array): PcapPacket {
  return { num, tsSec, tsUsec, capLen, origLen, raw, proto:'?', srcIp:'', dstIp:'', srcPort:null, dstPort:null, tcpFlags:0, icmpType:null, icmpCode:null, info:'', linkType:1 };
}

function parseTcp(raw: Uint8Array, o: number, si: string, di: string, b: PcapPacket): PcapPacket {
  if (raw.length < o+20) return {...b, proto:'TCP', srcIp:si, dstIp:di, info:'<short>'};
  const sp=r16be(raw,o), dp=r16be(raw,o+2), seq=r32be(raw,o+4), ack=r32be(raw,o+8), fl=raw[o+13], win=r16be(raw,o+14);
  return {...b, proto:'TCP', srcIp:si, dstIp:di, srcPort:sp, dstPort:dp, tcpFlags:fl, info:`[${tcpFlagsStr(fl)}] Seq=${seq} Ack=${ack} Win=${win}`};
}

function parseUdp(raw: Uint8Array, o: number, si: string, di: string, b: PcapPacket): PcapPacket {
  if (raw.length < o+8) return {...b, proto:'UDP', srcIp:si, dstIp:di, info:'<short>'};
  const sp=r16be(raw,o), dp=r16be(raw,o+2), len=r16be(raw,o+4);
  let info=`Len=${len-8}`;
  if (sp===53||dp===53) info=`DNS (${sp===53?'resp':'query'})`;
  else if (sp===67||dp===67||sp===68||dp===68) info='DHCP';
  else if (sp===123||dp===123) info='NTP';
  else if (sp===5353||dp===5353) info='mDNS';
  else if (sp===1900||dp===1900) info='SSDP';
  return {...b, proto:'UDP', srcIp:si, dstIp:di, srcPort:sp, dstPort:dp, info};
}

function parseIcmp4(raw: Uint8Array, o: number, si: string, di: string, b: PcapPacket): PcapPacket {
  if (raw.length < o+4) return {...b, proto:'ICMP', srcIp:si, dstIp:di};
  const t=raw[o], c=raw[o+1];
  return {...b, proto:'ICMP', srcIp:si, dstIp:di, icmpType:t, icmpCode:c, info:ICMP4[t]??`Type=${t}`};
}

function parseIcmp6(raw: Uint8Array, o: number, si: string, di: string, b: PcapPacket): PcapPacket {
  if (raw.length < o+4) return {...b, proto:'ICMPv6', srcIp:si, dstIp:di};
  const t=raw[o], c=raw[o+1];
  return {...b, proto:'ICMPv6', srcIp:si, dstIp:di, icmpType:t, icmpCode:c, info:ICMP6[t]??`Type=${t}`};
}

function parseArp(raw: Uint8Array, o: number, b: PcapPacket): PcapPacket {
  if (raw.length < o+28) return {...b, proto:'ARP', info:'ARP'};
  const op=r16be(raw,o+6), spa=ipv4Str(raw,o+14), tpa=ipv4Str(raw,o+24);
  const info = op===1?`Who has ${tpa}? Tell ${spa}`:op===2?`${spa} is at [MAC]`:`op=${op}`;
  return {...b, proto:'ARP', srcIp:spa, dstIp:tpa, info};
}

function parseIpv4(raw: Uint8Array, o: number, b: PcapPacket): PcapPacket {
  if (raw.length < o+20) return {...b, proto:'IPv4', info:'<short>'};
  const ihl=(raw[o]&0x0f)*4;
  const proto=raw[o+9], si=ipv4Str(raw,o+12), di=ipv4Str(raw,o+16), l4=o+ihl;
  if (proto===6)  return parseTcp(raw,l4,si,di,b);
  if (proto===17) return parseUdp(raw,l4,si,di,b);
  if (proto===1)  return parseIcmp4(raw,l4,si,di,b);
  return {...b, proto:`IP/${proto}`, srcIp:si, dstIp:di};
}

function parseIpv6(raw: Uint8Array, o: number, b: PcapPacket): PcapPacket {
  if (raw.length < o+40) return {...b, proto:'IPv6', info:'<short>'};
  const next=raw[o+6], si=ipv6Str(raw,o+8), di=ipv6Str(raw,o+24), l4=o+40;
  if (next===6)  return parseTcp(raw,l4,si,di,b);
  if (next===17) return parseUdp(raw,l4,si,di,b);
  if (next===58) return parseIcmp6(raw,l4,si,di,b);
  return {...b, proto:'IPv6', srcIp:si, dstIp:di, info:`next=${next}`};
}

function parseOnePacket(raw: Uint8Array, num: number, tsSec: number, tsUsec: number, capLen: number, origLen: number, linkType: number): PcapPacket {
  const b = { ...mkBase(num, tsSec, tsUsec, capLen, origLen, raw), linkType };
  let ethOff=0, et=0;
  if (linkType===1) {
    if (raw.length<14) return {...b, info:'<short frame>'};
    et=r16be(raw,12); ethOff=14;
    if (et===0x8100 && raw.length>=18) { et=r16be(raw,16); ethOff=18; }
  } else if (linkType===113) {
    if (raw.length<16) return {...b, info:'<short>'};
    et=r16be(raw,14); ethOff=16;
  } else if (linkType===228) { et=0x0800; }
  else if (linkType===229)   { et=0x86DD; }
  else return {...b, proto:`L2/${linkType}`};
  if (et===0x0800) return parseIpv4(raw,ethOff,b);
  if (et===0x86DD) return parseIpv6(raw,ethOff,b);
  if (et===0x0806) return parseArp(raw,ethOff,b);
  return {...b, proto:`0x${et.toString(16).padStart(4,'0')}`};
}

function parsePcap(buf: ArrayBuffer): PcapPacket[] | null {
  if (buf.byteLength < 24) return null;
  const full = new Uint8Array(buf);
  const magic = r32le(full, 0);
  let le: boolean, nsec: boolean;
  if      (magic===0xa1b2c3d4) { le=true;  nsec=false; }
  else if (magic===0xd4c3b2a1) { le=false; nsec=false; }
  else if (magic===0xa1b23c4d) { le=true;  nsec=true;  }
  else if (magic===0x4d3cb2a1) { le=false; nsec=true;  }
  else return null;
  const r32h = le ? r32le : r32be;
  const linkType = r32h(full, 20);
  const pkts: PcapPacket[] = [];
  let off=24, num=1;
  while (off+16 <= buf.byteLength) {
    const tsSec=r32h(full,off), tsFrac=r32h(full,off+4), capLen=r32h(full,off+8), origLen=r32h(full,off+12);
    off+=16;
    if (off+capLen > buf.byteLength) break;
    pkts.push(parseOnePacket(full.slice(off,off+capLen), num++, tsSec, nsec?Math.floor(tsFrac/1000):tsFrac, capLen, origLen, linkType));
    off+=capLen;
  }
  return pkts;
}

// ─── Filter ───────────────────────────────────────────────────────────────────

type FNode =
  | { op:'T'|'F' }
  | { op:'AND'|'OR'; l:FNode; r:FNode }
  | { op:'NOT'; e:FNode }
  | { op:'PROTO'; v:string }
  | { op:'CMP'; field:string; cmp:string; val:string|number };

type Tok = {t:'W';v:string}|{t:'N';v:number}|{t:'CMP';v:string}|{t:'AND'|'OR'|'NOT'|'LP'|'RP'|'EOF'};

function tokenize(s: string): Tok[] {
  const toks: Tok[]=[];
  let i=0;
  while (i<s.length) {
    if (/\s/.test(s[i]))            { i++; continue; }
    if (s.slice(i,i+2)==='&&')      { toks.push({t:'AND'}); i+=2; continue; }
    if (s.slice(i,i+2)==='||')      { toks.push({t:'OR'}); i+=2; continue; }
    if (s.slice(i,i+2)==='==')      { toks.push({t:'CMP',v:'=='}); i+=2; continue; }
    if (s.slice(i,i+2)==='!=')      { toks.push({t:'CMP',v:'!='}); i+=2; continue; }
    if (s.slice(i,i+2)==='<=')      { toks.push({t:'CMP',v:'<='}); i+=2; continue; }
    if (s.slice(i,i+2)==='>=')      { toks.push({t:'CMP',v:'>='}); i+=2; continue; }
    if (s[i]==='<')                  { toks.push({t:'CMP',v:'<'}); i++; continue; }
    if (s[i]==='>')                  { toks.push({t:'CMP',v:'>'}); i++; continue; }
    if (s[i]==='!')                  { toks.push({t:'NOT'}); i++; continue; }
    if (s[i]==='(')                  { toks.push({t:'LP'}); i++; continue; }
    if (s[i]===')')                  { toks.push({t:'RP'}); i++; continue; }
    if (/\d/.test(s[i])) {
      let j=i; while (j<s.length && /[\d.:]/.test(s[j])) j++;
      const w=s.slice(i,j);
      if (w.includes(':')||(w.includes('.')&&w.split('.').length===4)) toks.push({t:'W',v:w});
      else toks.push({t:'N',v:parseInt(w,10)});
      i=j; continue;
    }
    if (/[a-zA-Z_]/.test(s[i])) {
      let j=i; while (j<s.length && /[a-zA-Z0-9_.:/-]/.test(s[j])) j++;
      const w=s.slice(i,j);
      if (w==='and') toks.push({t:'AND'});
      else if (w==='or') toks.push({t:'OR'});
      else if (w==='not') toks.push({t:'NOT'});
      else toks.push({t:'W',v:w});
      i=j; continue;
    }
    i++;
  }
  toks.push({t:'EOF'}); return toks;
}

// Felder, die evalFilter tatsächlich auswertet. Ein Vergleich gegen ein
// unbekanntes Feld liefert dort still `true` (→ alle Pakete). Deshalb hier
// beim Parsen validieren, damit ein Tippfehler als Fehler sichtbar wird
// statt lautlos ins Leere zu filtern.
const FILTER_FIELDS = new Set([
  'ip.addr','host','ip.src','ip.src_host','ip.dst','ip.dst_host',
  'port','tcp.port','udp.port','tcp.srcport','udp.srcport','tcp.dstport','udp.dstport',
  'frame.len','ip.len','icmp.type',
  'tcp.flags','tcp.flags.syn','tcp.flags.fin','tcp.flags.rst','tcp.flags.ack',
]);

// Wirft bei syntaktisch/semantisch ungültigem Filter (unbekanntes Feld,
// überschüssige Tokens, unbekanntes Wort). Der Aufrufer (applyFilter →
// PcapPreview) fängt das und zeigt das Filter-Feld rot statt still alle
// Pakete durchzulassen.
function parseFilter(input: string): FNode {
  if (!input.trim()) return {op:'T'};
  const toks=tokenize(input); let p=0;
  const peek=()=>toks[p], eat=()=>toks[p++];
  const PROTOS=['tcp','udp','icmp','icmpv6','arp','ipv6','ip'];

  function or():FNode { let l=and(); while(peek().t==='OR'){eat();l={op:'OR',l,r:and()};} return l; }
  function and():FNode { let l=not(); while(peek().t==='AND'){eat();l={op:'AND',l,r:not()};} return l; }
  function not():FNode { if(peek().t==='NOT'){eat();return{op:'NOT',e:not()};} return prim(); }
  function prim():FNode {
    if (peek().t==='LP') { eat(); const n=or(); if(peek().t==='RP')eat(); else throw new Error('unclosed ('); return n; }
    if (peek().t==='W') {
      const w=(eat() as {t:'W';v:string}).v.toLowerCase();
      if (w==='host' && peek().t==='W') { const ip=(eat() as {t:'W';v:string}).v; return {op:'CMP',field:'ip.addr',cmp:'==',val:ip}; }
      if (w==='port' && peek().t==='N') { const n=(eat() as {t:'N';v:number}).v; return {op:'CMP',field:'port',cmp:'==',val:n}; }
      if (peek().t==='CMP') {
        const cmp=(eat() as {t:'CMP';v:string}).v;
        if (!FILTER_FIELDS.has(w)) throw new Error(`unknown field: ${w}`);
        let val:string|number='';
        if (peek().t==='W') val=(eat() as {t:'W';v:string}).v;
        else if (peek().t==='N') val=(eat() as {t:'N';v:number}).v;
        else throw new Error('missing value');
        return {op:'CMP',field:w,cmp,val};
      }
      if (PROTOS.includes(w)) return {op:'PROTO',v:w.toUpperCase()};
      throw new Error(`unexpected term: ${w}`);
    }
    throw new Error('expected term');
  }
  const tree=or();
  if (peek().t!=='EOF') throw new Error('trailing input');
  return tree;
}

function evalFilter(n: FNode, p: PcapPacket): boolean {
  if (n.op==='T') return true;
  if (n.op==='F') return false;
  if (n.op==='AND') return evalFilter(n.l,p)&&evalFilter(n.r,p);
  if (n.op==='OR')  return evalFilter(n.l,p)||evalFilter(n.r,p);
  if (n.op==='NOT') return !evalFilter(n.e,p);
  if (n.op==='PROTO') {
    const v=n.v;
    if (v==='TCP')    return p.proto==='TCP';
    if (v==='UDP')    return p.proto==='UDP';
    if (v==='ICMP')   return p.proto==='ICMP'||p.proto==='ICMPv6';
    if (v==='ICMPV6') return p.proto==='ICMPv6';
    if (v==='ARP')    return p.proto==='ARP';
    if (v==='IPV6')   return p.srcIp.includes(':');
    if (v==='IP')     return p.srcIp!==''&&!p.srcIp.includes(':');
    return p.proto.toUpperCase()===v;
  }
  if (n.op!=='CMP') return true;
  const {field,cmp,val}=n;
  const cmpV=(a:string|number|null):boolean=>{
    if (a===null) return false;
    if (cmp==='contains') return String(a).toLowerCase().includes(String(val).toLowerCase());
    if (cmp==='==') return String(a)===String(val)||a===val;
    if (cmp==='!=') return String(a)!==String(val)&&a!==val;
    const na=Number(a),nb=Number(val);
    if (cmp==='<') return na<nb; if (cmp==='>') return na>nb;
    if (cmp==='<=') return na<=nb; if (cmp==='>=') return na>=nb;
    return false;
  };
  if (field==='ip.addr'||field==='host') return cmpV(p.srcIp)||cmpV(p.dstIp);
  if (field==='ip.src'||field==='ip.src_host') return cmpV(p.srcIp);
  if (field==='ip.dst'||field==='ip.dst_host') return cmpV(p.dstIp);
  if (field==='port'||field==='tcp.port'||field==='udp.port') return (p.srcPort!==null&&cmpV(p.srcPort))||(p.dstPort!==null&&cmpV(p.dstPort));
  if (field==='tcp.srcport'||field==='udp.srcport') return cmpV(p.srcPort);
  if (field==='tcp.dstport'||field==='udp.dstport') return cmpV(p.dstPort);
  if (field==='frame.len'||field==='ip.len') return cmpV(p.origLen);
  if (field==='icmp.type') return cmpV(p.icmpType);
  if (field==='tcp.flags') return cmpV(p.tcpFlags);
  if (field==='tcp.flags.syn') return cmpV((p.tcpFlags>>1)&1);
  if (field==='tcp.flags.fin') return cmpV((p.tcpFlags>>0)&1);
  if (field==='tcp.flags.rst') return cmpV((p.tcpFlags>>2)&1);
  if (field==='tcp.flags.ack') return cmpV((p.tcpFlags>>4)&1);
  return true;
}

function applyFilter(pkts: PcapPacket[], s: string): PcapPacket[] {
  if (!s.trim()) return pkts;
  const tree = parseFilter(s);
  return pkts.filter(p => evalFilter(tree, p));
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function deltaTs(p: PcapPacket, base: PcapPacket): string {
  return ((p.tsSec-base.tsSec)+(p.tsUsec-base.tsUsec)/1_000_000).toFixed(6);
}

// ─── Layer-Decoder (Wireshark-artiger Protokoll-Baum für die Detail-Ansicht) ───
// Rein im Frontend — nutzt dieselben Offsets wie der Summary-Parser, gibt aber
// strukturierte Header-Felder pro Layer heraus. Alle Reads bounds-gecheckt
// (Snaplen 128 → höhere Layer können abgeschnitten sein).

interface DecField { name: string; value: string; }
interface DecLayer { name: string; fields: DecField[] }

function macStr(a: Uint8Array, o: number): string {
  if (o+6 > a.length) return '–';
  return Array.from(a.slice(o,o+6)).map(b=>b.toString(16).padStart(2,'0')).join(':');
}

const ETHERTYPES: Record<number,string> = { 0x0800:'IPv4', 0x86DD:'IPv6', 0x0806:'ARP', 0x8100:'802.1Q VLAN', 0x88CC:'LLDP' };
const IP_PROTOS: Record<number,string>  = { 1:'ICMP', 2:'IGMP', 6:'TCP', 17:'UDP', 41:'IPv6', 47:'GRE', 50:'ESP', 51:'AH', 58:'ICMPv6', 89:'OSPF', 103:'PIM', 112:'VRRP', 132:'SCTP' };
const ICMP4_CODES: Record<number,Record<number,string>> = {
  3: {0:'Net Unreachable',1:'Host Unreachable',2:'Protocol Unreachable',3:'Port Unreachable',4:'Frag Needed (DF)',13:'Communication Administratively Prohibited'},
  5: {0:'Redirect Network',1:'Redirect Host'},
  11:{0:'TTL Exceeded in Transit',1:'Frag Reassembly Time Exceeded'},
};

function tcpOptions(raw: Uint8Array, o: number, end: number): string {
  const parts: string[] = [];
  let i = o;
  while (i < end && i < raw.length) {
    const kind = raw[i];
    if (kind === 0) { parts.push('EOL'); break; }
    if (kind === 1) { parts.push('NOP'); i++; continue; }
    const len = raw[i+1];
    if (!len || i+len > raw.length) break;
    if (kind === 2 && len === 4)      parts.push(`MSS=${r16be(raw,i+2)}`);
    else if (kind === 3 && len === 3) parts.push(`WScale=${raw[i+2]}`);
    else if (kind === 4)              parts.push('SACK-Perm');
    else if (kind === 5)              parts.push('SACK');
    else if (kind === 8 && len === 10) parts.push(`TSval=${r32be(raw,i+2)} TSecr=${r32be(raw,i+6)}`);
    else parts.push(`opt${kind}`);
    i += len;
  }
  return parts.join(', ');
}

function appHint(raw: Uint8Array, o: number, proto: string, sp: number|null, dp: number|null): DecLayer | null {
  if (o >= raw.length) return null;
  const port = (p: number) => sp === p || dp === p;
  const ascii = (s: number, e: number) => Array.from(raw.slice(s, Math.min(e, raw.length))).map(b => (b>=32&&b<127)?String.fromCharCode(b):'.').join('');

  // HTTP: Request-Line / Status-Line + Host-Header (heuristisch über die
  // Payload, port-agnostisch; TLS wird danach separat erkannt).
  if (proto === 'TCP') {
    const head = ascii(o, o+8);
    if (/^(GET|POST|PUT|HEAD|DELETE|PATCH|OPTIONS|HTTP\/)/.test(head)) {
      const text = ascii(o, raw.length);
      const line = text.split('\r\n')[0] || text.split('\n')[0] || '';
      const host = (text.match(/\r?\nHost:\s*([^\r\n]+)/i) || [])[1];
      const f: DecField[] = [{name:'Request', value: line.slice(0,80)}];
      if (host) f.push({name:'Host', value: host.slice(0,60)});
      return {name:'HTTP', fields:f};
    }
  }
  // TLS ClientHello → SNI
  if (proto === 'TCP' && port(443) && raw[o]===0x16 && raw[o+1]===0x03 && raw[o+5]===0x01) {
    const sni = tlsSni(raw, o);
    return {name:'TLS', fields:[{name:'Record', value:'Handshake · ClientHello'}, ...(sni?[{name:'SNI', value:sni}]:[])]};
  }
  // DNS (UDP/53): ID, QR, erste Query
  if ((proto==='UDP'||proto==='TCP') && port(53) && o+12 <= raw.length) {
    const base = proto==='TCP' ? o+2 : o;   // TCP-DNS hat 2 Byte Length-Präfix
    if (base+12 <= raw.length) {
      const flags = r16be(raw, base+2);
      const qr = (flags>>15)&1;
      const qname = dnsName(raw, base+12);
      return {name:'DNS', fields:[
        {name:'ID', value:'0x'+r16be(raw,base).toString(16).padStart(4,'0')},
        {name:'Type', value: qr?'Response':'Query'},
        ...(qname?[{name:'Name', value:qname}]:[]),
      ]};
    }
  }
  // Modbus/TCP (502): MBAP + Function Code
  if (proto==='TCP' && port(502) && o+8 <= raw.length) {
    const fn = raw[o+7];
    return {name:'Modbus/TCP', fields:[
      {name:'Transaction', value:String(r16be(raw,o))},
      {name:'Unit ID', value:String(raw[o+6])},
      {name:'Function', value:`${fn} (0x${fn.toString(16)})`},
    ]};
  }
  // S7comm (102): TPKT/COTP → S7 ROSCTR
  if (proto==='TCP' && port(102) && o+8 <= raw.length && raw[o]===0x03) {
    const cotpLen = raw[o+4];
    const s7 = o+5+cotpLen;
    const f: DecField[] = [{name:'TPKT', value:`v${raw[o]} len=${r16be(raw,o+2)}`}];
    if (s7+2 <= raw.length && raw[s7]===0x32) {
      const ros = raw[s7+1];
      const ROS: Record<number,string> = {1:'Job Request',2:'Ack',3:'Ack-Data',7:'Userdata'};
      f.push({name:'S7 ROSCTR', value: ROS[ros] ?? String(ros)});
    }
    return {name:'S7comm', fields:f};
  }
  return null;
}

function tlsSni(raw: Uint8Array, o: number): string | null {
  // TLS record(5) + handshake(4) + version(2) + random(32) → session/cipher/ext.
  try {
    let p = o + 5 + 4 + 2 + 32;
    if (p >= raw.length) return null;
    p += 1 + raw[p];                                   // session id
    if (p+2 > raw.length) return null;
    p += 2 + r16be(raw, p);                            // cipher suites
    if (p+1 > raw.length) return null;
    p += 1 + raw[p];                                   // compression
    if (p+2 > raw.length) return null;
    let extEnd = p + 2 + r16be(raw, p); p += 2;        // extensions block
    extEnd = Math.min(extEnd, raw.length);
    while (p + 4 <= extEnd) {
      const type = r16be(raw, p), len = r16be(raw, p+2); p += 4;
      if (type === 0) {                                // server_name
        // server_name_list(2) + type(1) + name_len(2) + name
        const nameLen = r16be(raw, p+3);
        const s = p+5;
        if (s+nameLen <= raw.length) return Array.from(raw.slice(s, s+nameLen)).map(b=>String.fromCharCode(b)).join('');
        return null;
      }
      p += len;
    }
  } catch { /* truncated */ }
  return null;
}

function dnsName(raw: Uint8Array, o: number): string {
  const labels: string[] = [];
  let p = o, guard = 0;
  while (p < raw.length && guard++ < 20) {
    const len = raw[p];
    if (len === 0) break;
    if ((len & 0xc0) === 0xc0) break;                  // Pointer — Snaplen-Kontext, abbrechen
    if (p+1+len > raw.length) break;
    labels.push(Array.from(raw.slice(p+1, p+1+len)).map(b=>String.fromCharCode(b)).join(''));
    p += 1 + len;
  }
  return labels.join('.');
}

function decodeLayers(raw: Uint8Array, linkType: number): DecLayer[] {
  const layers: DecLayer[] = [];
  let et = 0, off = 0;

  if (linkType === 1) {
    if (raw.length < 14) return layers;
    et = r16be(raw, 12); off = 14;
    const f: DecField[] = [
      {name:'Destination', value: macStr(raw,0)},
      {name:'Source', value: macStr(raw,6)},
    ];
    if (et === 0x8100 && raw.length >= 18) {
      f.push({name:'VLAN', value:String(r16be(raw,14) & 0x0fff)});
      et = r16be(raw,16); off = 18;
    }
    f.push({name:'EtherType', value:`${ETHERTYPES[et] ?? '?'} (0x${et.toString(16).padStart(4,'0')})`});
    layers.push({name:'Ethernet II', fields:f});
  } else if (linkType === 113) {
    if (raw.length < 16) return layers;
    et = r16be(raw,14); off = 16;
    layers.push({name:'Linux SLL', fields:[{name:'EtherType', value:`${ETHERTYPES[et] ?? '?'} (0x${et.toString(16).padStart(4,'0')})`}]});
  } else if (linkType === 228) { et = 0x0800; }
  else if (linkType === 229)   { et = 0x86DD; }
  else { layers.push({name:`LinkType ${linkType}`, fields:[]}); return layers; }

  if (et === 0x0806) { decodeArp(raw, off, layers); return layers; }
  if (et === 0x0800) decodeIpv4(raw, off, layers);
  else if (et === 0x86DD) decodeIpv6(raw, off, layers);
  return layers;
}

function decodeArp(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+28 > raw.length) { layers.push({name:'ARP', fields:[{name:'(truncated)', value:''}]}); return; }
  const op = r16be(raw,o+6);
  layers.push({name:'ARP', fields:[
    {name:'Operation', value: op===1?'Request (1)': op===2?'Reply (2)':String(op)},
    {name:'Sender MAC', value: macStr(raw,o+8)},
    {name:'Sender IP', value: ipv4Str(raw,o+14)},
    {name:'Target MAC', value: macStr(raw,o+18)},
    {name:'Target IP', value: ipv4Str(raw,o+24)},
  ]});
}

function decodeIpv4(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+20 > raw.length) { layers.push({name:'IPv4', fields:[{name:'(truncated)', value:''}]}); return; }
  const ihl = (raw[o]&0x0f)*4, proto = raw[o+9], flags = raw[o+6]>>5, frag = r16be(raw,o+6)&0x1fff;
  layers.push({name:'IPv4', fields:[
    {name:'Version', value:String(raw[o]>>4)},
    {name:'Header Length', value:`${ihl} B`},
    {name:'DSCP/ECN', value:`0x${raw[o+1].toString(16).padStart(2,'0')}`},
    {name:'Total Length', value:String(r16be(raw,o+2))},
    {name:'Identification', value:'0x'+r16be(raw,o+4).toString(16).padStart(4,'0')},
    {name:'Flags', value:`${flags&2?'DF ':''}${flags&1?'MF':''}`.trim() || '–'},
    {name:'Fragment Offset', value:String(frag)},
    {name:'TTL', value:String(raw[o+8])},
    {name:'Protocol', value:`${IP_PROTOS[proto] ?? '?'} (${proto})`},
    {name:'Checksum', value:'0x'+r16be(raw,o+10).toString(16).padStart(4,'0')},
    {name:'Source', value: ipv4Str(raw,o+12)},
    {name:'Destination', value: ipv4Str(raw,o+16)},
  ]});
  const l4 = o+ihl;
  if (proto===6)  decodeTcp(raw,l4,layers);
  else if (proto===17) decodeUdp(raw,l4,layers);
  else if (proto===1)  decodeIcmp4(raw,l4,layers);
}

function decodeIpv6(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+40 > raw.length) { layers.push({name:'IPv6', fields:[{name:'(truncated)', value:''}]}); return; }
  const next = raw[o+6];
  layers.push({name:'IPv6', fields:[
    {name:'Version', value:String(raw[o]>>4)},
    {name:'Payload Length', value:String(r16be(raw,o+4))},
    {name:'Next Header', value:`${IP_PROTOS[next] ?? '?'} (${next})`},
    {name:'Hop Limit', value:String(raw[o+7])},
    {name:'Source', value: ipv6Str(raw,o+8)},
    {name:'Destination', value: ipv6Str(raw,o+24)},
  ]});
  const l4 = o+40;
  if (next===6)  decodeTcp(raw,l4,layers);
  else if (next===17) decodeUdp(raw,l4,layers);
  else if (next===58) decodeIcmp6(raw,l4,layers);
}

function decodeTcp(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+20 > raw.length) { layers.push({name:'TCP', fields:[{name:'(truncated)', value:''}]}); return; }
  const sp=r16be(raw,o), dp=r16be(raw,o+2), doff=(raw[o+12]>>4)*4, fl=raw[o+13];
  const opts = doff>20 ? tcpOptions(raw, o+20, o+doff) : '';
  layers.push({name:'TCP', fields:[
    {name:'Source Port', value:String(sp)},
    {name:'Destination Port', value:String(dp)},
    {name:'Sequence', value:String(r32be(raw,o+4))},
    {name:'Acknowledgment', value:String(r32be(raw,o+8))},
    {name:'Header Length', value:`${doff} B`},
    {name:'Flags', value: tcpFlagsStr(fl)},
    {name:'Window', value:String(r16be(raw,o+14))},
    {name:'Checksum', value:'0x'+r16be(raw,o+16).toString(16).padStart(4,'0')},
    ...(opts?[{name:'Options', value:opts}]:[]),
  ]});
  const h = appHint(raw, o+doff, 'TCP', sp, dp); if (h) layers.push(h);
}

function decodeUdp(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+8 > raw.length) { layers.push({name:'UDP', fields:[{name:'(truncated)', value:''}]}); return; }
  const sp=r16be(raw,o), dp=r16be(raw,o+2);
  layers.push({name:'UDP', fields:[
    {name:'Source Port', value:String(sp)},
    {name:'Destination Port', value:String(dp)},
    {name:'Length', value:String(r16be(raw,o+4))},
    {name:'Checksum', value:'0x'+r16be(raw,o+6).toString(16).padStart(4,'0')},
  ]});
  const h = appHint(raw, o+8, 'UDP', sp, dp); if (h) layers.push(h);
}

function decodeIcmp4(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+4 > raw.length) { layers.push({name:'ICMP', fields:[{name:'(truncated)', value:''}]}); return; }
  const t=raw[o], c=raw[o+1];
  const codeName = ICMP4_CODES[t]?.[c];
  layers.push({name:'ICMP', fields:[
    {name:'Type', value:`${ICMP4[t] ?? '?'} (${t})`},
    {name:'Code', value: codeName ? `${codeName} (${c})` : String(c)},
    {name:'Checksum', value:'0x'+r16be(raw,o+2).toString(16).padStart(4,'0')},
  ]});
}

function decodeIcmp6(raw: Uint8Array, o: number, layers: DecLayer[]) {
  if (o+4 > raw.length) { layers.push({name:'ICMPv6', fields:[{name:'(truncated)', value:''}]}); return; }
  const t=raw[o], c=raw[o+1];
  layers.push({name:'ICMPv6', fields:[
    {name:'Type', value:`${ICMP6[t] ?? '?'} (${t})`},
    {name:'Code', value:String(c)},
    {name:'Checksum', value:'0x'+r16be(raw,o+2).toString(16).padStart(4,'0')},
  ]});
}

// xxd-artiger Hex+ASCII-Dump mit Byte-Offset.
function hexDumpLines(arr: Uint8Array, maxBytes=128): { off: string; hex: string; ascii: string }[] {
  const out: { off: string; hex: string; ascii: string }[] = [];
  const n = Math.min(arr.length, maxBytes);
  for (let i = 0; i < n; i += 16) {
    const slice = arr.slice(i, Math.min(i+16, n));
    const hex = Array.from(slice).map(b=>b.toString(16).padStart(2,'0')).join(' ').padEnd(16*3-1, ' ');
    const ascii = Array.from(slice).map(b=>(b>=32&&b<127)?String.fromCharCode(b):'.').join('');
    out.push({ off: i.toString(16).padStart(4,'0'), hex, ascii });
  }
  return out;
}

const PROTO_CLS: Record<string,string> = { TCP:'text-blue-300', UDP:'text-green-300', ICMP:'text-yellow-300', ICMPv6:'text-yellow-400', ARP:'text-purple-300' };

const ROW_H = 22;   // px — must match the rendered row height
const OVERSCAN = 30;

// ─── Component ────────────────────────────────────────────────────────────────

export function PcapPreview({ alertId, filename, onClose }: { alertId:string; filename?:string; onClose:()=>void }) {
  const { t } = useTranslation();
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string|null>(null);
  const [packets, setPackets]     = useState<PcapPacket[]>([]);
  const [rawBuf, setRawBuf]       = useState<ArrayBuffer|null>(null);
  const [filter, setFilter]       = useState('');
  const [filterErr, setFilterErr] = useState(false);
  const [selected, setSelected]   = useState<number|null>(null);
  const [dl, setDl]               = useState(false);
  // false = nur die Pakete des Alert-Flows (server-seitig gefiltert)
  // true  = ungefiltertes ±60s-Capture-Fenster aus pcap-store
  const [rawMode, setRawMode]     = useState(false);

  // ESC schließt – konsistent mit AlertFlowPopup, HostConnectionDrawer.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH]         = useState(500);

  const fn = (filename ?? `alert-${alertId.slice(0,8)}.pcap`).replace(
    /(\.pcap)?$/,
    rawMode ? '-full.pcap' : '-filtered.pcap'
  );

  useEffect(() => {
    let alive=true;
    setLoading(true); setError(null); setSelected(null);
    const tok=getToken();
    fetch(pcapUrl(alertId, rawMode), { headers:tok?{Authorization:`Bearer ${tok}`}:{} })
      .then(r=>{ if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.arrayBuffer(); })
      .then(buf=>{
        if (!alive) return;
        const pkts=parsePcap(buf);
        if (!pkts) throw new Error(t('pcap.invalidFormat'));
        setRawBuf(buf); setPackets(pkts); setLoading(false);
      })
      .catch(e=>{ if(alive){ setError(e.message); setLoading(false); } });
    return ()=>{ alive=false; };
  }, [alertId, rawMode]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setViewH(el.clientHeight));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  const filtered = useMemo(()=>{
    try { const r=applyFilter(packets,filter); setFilterErr(false); return r; }
    catch { setFilterErr(true); return packets; }
  }, [packets, filter]);

  const visStart = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
  const visEnd   = Math.min(filtered.length, Math.ceil((scrollTop + viewH) / ROW_H) + OVERSCAN);
  const topPad   = visStart * ROW_H;
  const botPad   = Math.max(0, (filtered.length - visEnd) * ROW_H);

  const selPkt = selected!==null ? filtered.find(p=>p.num===selected)??null : null;
  // Decodierter Layer-Baum + xxd-Dump für die Detail-Ansicht (memoisiert pro Paket).
  const decoded = useMemo(() => selPkt ? decodeLayers(selPkt.raw, selPkt.linkType) : [], [selPkt]);
  const dump    = useMemo(() => selPkt ? hexDumpLines(selPkt.raw) : [], [selPkt]);

  const download = useCallback(async()=>{
    if (!rawBuf||dl) return;
    setDl(true);
    const blob=new Blob([rawBuf],{type:'application/vnd.tcpdump.pcap'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=fn; a.click();
    URL.revokeObjectURL(url); setDl(false);
  },[rawBuf,fn,dl]);

  const base = filtered[0]??null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-end md:items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative bg-slate-900 border border-slate-700 shadow-2xl flex flex-col overflow-hidden w-full h-[100dvh] rounded-none md:w-[92vw] md:max-w-[1320px] md:h-[82dvh] md:max-h-[calc(100dvh-32px)] md:rounded-lg"
        onClick={e=>e.stopPropagation()}
      >
        {/* Header — auf Mobile flex-wrap, ESC-Button immer erreichbar */}
        <div className="flex flex-wrap items-center gap-2 md:gap-3 px-3 py-2 md:px-4 md:py-3 border-b border-slate-700 shrink-0">
          <svg className="w-4 h-4 text-cyan-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>
          </svg>
          <span className="text-slate-300 font-mono text-xs md:text-sm truncate flex-1 min-w-0">
            {t('pcap.preview')} — <span className="text-cyan-400">{fn}</span>
          </span>

          {/* Close-Button steht direkt neben dem Filename-Span — so kann er
              auf Mobile nicht nach hinten herausgequetscht werden, wenn
              "Vollständiges Fenster" + Download umbrechen. min-w 44px für
              sicheren Touch. */}
          <button onClick={onClose} title={t('common.close')}
            className="text-[11px] px-3 py-2 md:py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors min-w-[44px] flex items-center justify-center shrink-0">
            <span className="hidden md:inline">ESC · </span>✕
          </button>

          {/* Raw-Mode-Toggle + Download wickeln auf Mobile in eine eigene
              Zeile (basis-full), auf Desktop bleiben sie inline. */}
          <div className="flex items-center gap-2 basis-full md:basis-auto md:ml-auto">
            <label
              className="flex items-center gap-1.5 text-[11px] text-slate-400 cursor-pointer select-none whitespace-nowrap"
              title={t('pcap.fullWindowTitle')}
            >
              <input
                type="checkbox"
                checked={rawMode}
                onChange={e => setRawMode(e.target.checked)}
                disabled={loading}
                className="cursor-pointer accent-cyan-500 w-4 h-4"
              />
              {t('pcap.fullWindow')}
            </label>

            {rawBuf && (
              <button onClick={download} disabled={dl}
                className="px-3 py-1.5 md:py-1 text-xs rounded border border-cyan-700/50 text-cyan-400 bg-cyan-950/30 hover:bg-cyan-900/40 transition-colors disabled:opacity-50 whitespace-nowrap">
                {dl?'…':t('pcap.download')}
              </button>
            )}
          </div>
        </div>

        {/* Filter bar */}
        {!loading && !error && (
          <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-700/50 shrink-0">
            <span className="text-[11px] text-slate-500 whitespace-nowrap font-mono">{t('pcap.filter')}</span>
            <input
              type="text" value={filter} spellCheck={false}
              onChange={e=>setFilter(e.target.value)}
              placeholder="tcp.port == 443   ip.src == 10.0.0.1   udp and not port 53   tcp.flags.syn == 1"
              className={`flex-1 bg-slate-800 border rounded px-2 py-1 text-xs font-mono outline-none transition-colors placeholder:text-slate-600 ${
                filterErr ? 'border-red-600 text-red-300' : filter ? 'border-green-700 text-green-200' : 'border-slate-600 text-slate-200'
              }`}
            />
            {filter && (
              <button onClick={()=>setFilter('')} className="text-slate-500 hover:text-slate-300 text-xs px-1">✕</button>
            )}
            <span className="text-[11px] text-slate-500 font-mono whitespace-nowrap">
              {t('pcap.packetsCount', { filtered: filtered.length, total: packets.length })}
            </span>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {loading ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">{t('pcap.loading')}</div>
          ) : error ? (
            <div className="flex-1 flex items-center justify-center text-red-400 text-sm">{t('common.error', { message: error })}</div>
          ) : packets.length===0 ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">{t('pcap.empty')}</div>
          ) : (
            <>
              {/* Packet list — virtual scroll */}
              <div ref={scrollRef} className="flex-1 overflow-y-auto min-h-0 overscroll-contain" onScroll={handleScroll}>
                <table className="w-full border-collapse text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900/95 backdrop-blur-sm z-10">
                    <tr className="text-left text-slate-500 border-b border-slate-700 text-[11px]">
                      <th className="px-2 py-1.5 w-10">{t('pcap.columns.num')}</th>
                      <th className="px-2 py-1.5 w-24">{t('pcap.columns.time')}</th>
                      <th className="px-2 py-1.5">{t('pcap.columns.source')}</th>
                      <th className="px-2 py-1.5">{t('pcap.columns.destination')}</th>
                      <th className="px-2 py-1.5 w-16">{t('pcap.columns.proto')}</th>
                      <th className="px-2 py-1.5 w-12">{t('pcap.columns.len')}</th>
                      <th className="px-2 py-1.5">{t('pcap.columns.info')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length===0 ? (
                      <tr><td colSpan={7} className="text-center text-slate-600 py-10">{t('pcap.noFilterMatch')}</td></tr>
                    ) : (
                      <>
                        {topPad > 0 && <tr style={{height: topPad}}><td colSpan={7}/></tr>}
                        {filtered.slice(visStart, visEnd).map(pkt=>(
                          <tr
                            key={pkt.num}
                            style={{height: ROW_H}}
                            onClick={()=>setSelected(pkt.num===selected?null:pkt.num)}
                            className={`border-b border-slate-800/50 cursor-pointer transition-colors ${
                              pkt.num===selected ? 'bg-cyan-900/25 border-cyan-800/40' : 'hover:bg-slate-800/60'
                            }`}
                          >
                            <td className="px-2 py-0.5 text-slate-600">{pkt.num}</td>
                            <td className="px-2 py-0.5 text-slate-400 tabular-nums">{base?deltaTs(pkt,base):'0.000000'}</td>
                            <td className="px-2 py-0.5 text-slate-300 whitespace-nowrap">{pkt.srcIp}{pkt.srcPort!==null?`:${pkt.srcPort}`:''}</td>
                            <td className="px-2 py-0.5 text-slate-300 whitespace-nowrap">{pkt.dstIp}{pkt.dstPort!==null?`:${pkt.dstPort}`:''}</td>
                            <td className={`px-2 py-0.5 font-semibold ${PROTO_CLS[pkt.proto]??'text-slate-400'}`}>{pkt.proto}</td>
                            <td className="px-2 py-0.5 text-slate-500 tabular-nums">{pkt.origLen}</td>
                            <td className="px-2 py-0.5 text-slate-400 truncate max-w-xs">{pkt.info}</td>
                          </tr>
                        ))}
                        {botPad > 0 && <tr style={{height: botPad}}><td colSpan={7}/></tr>}
                      </>
                    )}
                  </tbody>
                </table>
              </div>

              {/* Detail panel — decodierter Protokoll-Baum + xxd-Dump */}
              {selPkt && (
                <div className="shrink-0 border-t border-slate-700 bg-slate-950/80 px-4 py-3 max-h-72 overflow-y-auto">
                  <div className="text-xs font-mono space-y-2">
                    <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-slate-400">
                      <span>{t('pcap.detail.packet')} <span className="text-slate-200">#{selPkt.num}</span></span>
                      <span>{t('pcap.detail.proto')} <span className={PROTO_CLS[selPkt.proto]??'text-slate-200'}>{selPkt.proto}</span></span>
                      {selPkt.srcIp&&<span>{t('pcap.detail.from')} <span className="text-slate-200">{selPkt.srcIp}{selPkt.srcPort!=null?`:${selPkt.srcPort}`:''}</span></span>}
                      {selPkt.dstIp&&<span>{t('pcap.detail.to')} <span className="text-slate-200">{selPkt.dstIp}{selPkt.dstPort!=null?`:${selPkt.dstPort}`:''}</span></span>}
                      <span>{t('pcap.detail.captured')} <span className="text-slate-200">{selPkt.capLen}</span> / {t('pcap.detail.original')} <span className="text-slate-200">{selPkt.origLen}</span> B</span>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-2">
                      {/* Layer-Baum */}
                      <div className="space-y-1.5">
                        {decoded.length === 0 && <div className="text-slate-600">{t('pcap.detail.noDecode')}</div>}
                        {decoded.map((layer, li) => (
                          <div key={li}>
                            <div className="text-cyan-300/90 font-semibold">{layer.name}</div>
                            <div className="pl-3 border-l border-slate-700/60 mt-0.5 space-y-0.5">
                              {layer.fields.map((fld, fi) => (
                                <div key={fi} className="flex gap-2">
                                  <span className="text-slate-500 shrink-0 min-w-[130px]">{fld.name}</span>
                                  <span className="text-slate-200 break-all">{fld.value}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* xxd-Hex+ASCII-Dump */}
                      <div>
                        <div className="text-slate-500 mb-0.5">
                          {t('pcap.detail.hexDump')}
                          {selPkt.raw.length>=128 && <span className="text-slate-700"> {t('pcap.detail.snaplen')}</span>}
                        </div>
                        <div className="leading-tight whitespace-pre text-[11px]">
                          {dump.map((l, i) => (
                            <div key={i}>
                              <span className="text-slate-600">{l.off}</span>{'  '}
                              <span className="text-slate-400">{l.hex}</span>{'  '}
                              <span className="text-emerald-300/70">{l.ascii}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
