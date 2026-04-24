import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
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
    return `${pre}::${suf}`.replace(/^:|:$/, '');
  }
  return g.join(':');
}

const TCP_FLAG_NAMES = ['FIN','SYN','RST','PSH','ACK','URG'];
function tcpFlagsStr(f: number) { return TCP_FLAG_NAMES.filter((_,i) => f & (1<<i)).join(',') || '.'; }

const ICMP4: Record<number,string> = { 0:'Echo Reply', 3:'Dest Unreachable', 5:'Redirect', 8:'Echo Request', 11:'TTL Exceeded', 12:'Param Problem' };
const ICMP6: Record<number,string> = { 1:'Dest Unreachable', 2:'Packet Too Big', 3:'TTL Exceeded', 128:'Echo Request', 129:'Echo Reply', 133:'Router Solicitation', 134:'Router Advertisement', 135:'Neighbor Solicitation', 136:'Neighbor Advertisement' };

function mkBase(num: number, tsSec: number, tsUsec: number, capLen: number, origLen: number, raw: Uint8Array): PcapPacket {
  return { num, tsSec, tsUsec, capLen, origLen, raw, proto:'?', srcIp:'', dstIp:'', srcPort:null, dstPort:null, tcpFlags:0, icmpType:null, icmpCode:null, info:'' };
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
  const b = mkBase(num, tsSec, tsUsec, capLen, origLen, raw);
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

function parseFilter(input: string): FNode {
  if (!input.trim()) return {op:'T'};
  try {
    const toks=tokenize(input); let p=0;
    const peek=()=>toks[p], eat=()=>toks[p++];
    const PROTOS=['tcp','udp','icmp','icmpv6','arp','ipv6','ip'];

    function or():FNode { let l=and(); while(peek().t==='OR'){eat();l={op:'OR',l,r:and()};} return l; }
    function and():FNode { let l=not(); while(peek().t==='AND'){eat();l={op:'AND',l,r:not()};} return l; }
    function not():FNode { if(peek().t==='NOT'){eat();return{op:'NOT',e:not()};} return prim(); }
    function prim():FNode {
      if (peek().t==='LP') { eat(); const n=or(); if(peek().t==='RP')eat(); return n; }
      if (peek().t==='W') {
        const w=(eat() as {t:'W';v:string}).v.toLowerCase();
        if (w==='host' && peek().t==='W') { const ip=(eat() as {t:'W';v:string}).v; return {op:'CMP',field:'ip.addr',cmp:'==',val:ip}; }
        if (w==='port' && peek().t==='N') { const n=(eat() as {t:'N';v:number}).v; return {op:'CMP',field:'port',cmp:'==',val:n}; }
        if (peek().t==='CMP') {
          const cmp=(eat() as {t:'CMP';v:string}).v;
          let val:string|number='';
          if (peek().t==='W') val=(eat() as {t:'W';v:string}).v;
          else if (peek().t==='N') val=(eat() as {t:'N';v:number}).v;
          return {op:'CMP',field:w,cmp,val};
        }
        if (PROTOS.includes(w)) return {op:'PROTO',v:w.toUpperCase()};
        return {op:'T'};
      }
      return {op:'T'};
    }
    return or();
  } catch { return {op:'T'}; }
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

function hexLine(arr: Uint8Array, maxBytes=128): string {
  return Array.from(arr.slice(0,maxBytes)).map(b=>b.toString(16).padStart(2,'0')).join(' ');
}

const PROTO_CLS: Record<string,string> = { TCP:'text-blue-300', UDP:'text-green-300', ICMP:'text-yellow-300', ICMPv6:'text-yellow-400', ARP:'text-purple-300' };

const ROW_H = 22;   // px — must match the rendered row height
const OVERSCAN = 30;

// ─── Component ────────────────────────────────────────────────────────────────

export function PcapPreview({ alertId, filename, onClose }: { alertId:string; filename?:string; onClose:()=>void }) {
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string|null>(null);
  const [packets, setPackets]     = useState<PcapPacket[]>([]);
  const [rawBuf, setRawBuf]       = useState<ArrayBuffer|null>(null);
  const [filter, setFilter]       = useState('');
  const [filterErr, setFilterErr] = useState(false);
  const [selected, setSelected]   = useState<number|null>(null);
  const [dl, setDl]               = useState(false);

  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewH, setViewH]         = useState(500);

  const fn = filename ?? `alert-${alertId.slice(0,8)}.pcap`;

  useEffect(() => {
    let alive=true;
    setLoading(true); setError(null);
    const tok=getToken();
    fetch(pcapUrl(alertId), { headers:tok?{Authorization:`Bearer ${tok}`}:{} })
      .then(r=>{ if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.arrayBuffer(); })
      .then(buf=>{
        if (!alive) return;
        const pkts=parsePcap(buf);
        if (!pkts) throw new Error('Kein gültiges PCAP-Format');
        setRawBuf(buf); setPackets(pkts); setLoading(false);
      })
      .catch(e=>{ if(alive){ setError(e.message); setLoading(false); } });
    return ()=>{ alive=false; };
  }, [alertId]);

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

  const download = useCallback(async()=>{
    if (!rawBuf||dl) return;
    setDl(true);
    const blob=new Blob([rawBuf],{type:'application/vnd.tcpdump.pcap'});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a'); a.href=url; a.download=fn; a.click();
    URL.revokeObjectURL(url); setDl(false);
  },[rawBuf,fn,dl]);

  const base = filtered[0]??null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="relative bg-slate-900 border border-slate-700 rounded-lg shadow-2xl flex flex-col overflow-hidden"
        style={{width:'92vw', maxWidth:'1320px', height:'82dvh', maxHeight:'calc(100dvh - 32px)'}}
        onClick={e=>e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-700 shrink-0">
          <svg className="w-4 h-4 text-cyan-500 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/>
          </svg>
          <span className="text-slate-300 font-mono text-sm truncate">
            PCAP Vorschau — <span className="text-cyan-400">{fn}</span>
          </span>
          <div className="flex-1"/>
          {rawBuf && (
            <button onClick={download} disabled={dl}
              className="px-3 py-1 text-xs rounded border border-cyan-700/50 text-cyan-400 bg-cyan-950/30 hover:bg-cyan-900/40 transition-colors disabled:opacity-50 whitespace-nowrap">
              {dl?'…':'↓ Download'}
            </button>
          )}
          <button onClick={onClose}
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700 transition-colors text-sm">
            ✕
          </button>
        </div>

        {/* Filter bar */}
        {!loading && !error && (
          <div className="flex items-center gap-2 px-4 py-2 border-b border-slate-700/50 shrink-0">
            <span className="text-[11px] text-slate-500 whitespace-nowrap font-mono">Filter</span>
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
              {filtered.length} / {packets.length} Pakete
            </span>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-hidden flex flex-col min-h-0">
          {loading ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">Lade PCAP…</div>
          ) : error ? (
            <div className="flex-1 flex items-center justify-center text-red-400 text-sm">Fehler: {error}</div>
          ) : packets.length===0 ? (
            <div className="flex-1 flex items-center justify-center text-slate-500 text-sm">Keine Pakete im PCAP</div>
          ) : (
            <>
              {/* Packet list — virtual scroll */}
              <div ref={scrollRef} className="flex-1 overflow-y-auto min-h-0 overscroll-contain" onScroll={handleScroll}>
                <table className="w-full border-collapse text-xs font-mono">
                  <thead className="sticky top-0 bg-slate-900/95 backdrop-blur-sm z-10">
                    <tr className="text-left text-slate-500 border-b border-slate-700 text-[11px]">
                      <th className="px-2 py-1.5 w-10">#</th>
                      <th className="px-2 py-1.5 w-24">Zeit (s)</th>
                      <th className="px-2 py-1.5">Quelle</th>
                      <th className="px-2 py-1.5">Ziel</th>
                      <th className="px-2 py-1.5 w-16">Proto</th>
                      <th className="px-2 py-1.5 w-12">Len</th>
                      <th className="px-2 py-1.5">Info</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.length===0 ? (
                      <tr><td colSpan={7} className="text-center text-slate-600 py-10">Kein Paket entspricht dem Filter</td></tr>
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

              {/* Detail panel */}
              {selPkt && (
                <div className="shrink-0 border-t border-slate-700 bg-slate-950/80 px-4 py-3 max-h-40 overflow-y-auto">
                  <div className="text-xs font-mono space-y-1.5">
                    <div className="flex flex-wrap gap-x-4 gap-y-0.5 text-slate-400">
                      <span>Paket <span className="text-slate-200">#{selPkt.num}</span></span>
                      <span>Proto <span className={PROTO_CLS[selPkt.proto]??'text-slate-200'}>{selPkt.proto}</span></span>
                      {selPkt.srcIp&&<span>Von <span className="text-slate-200">{selPkt.srcIp}{selPkt.srcPort!=null?`:${selPkt.srcPort}`:''}</span></span>}
                      {selPkt.dstIp&&<span>Nach <span className="text-slate-200">{selPkt.dstIp}{selPkt.dstPort!=null?`:${selPkt.dstPort}`:''}</span></span>}
                      <span>Captured <span className="text-slate-200">{selPkt.capLen}</span> / Original <span className="text-slate-200">{selPkt.origLen}</span> B</span>
                      {selPkt.tcpFlags!==0&&<span>Flags <span className="text-slate-200">{tcpFlagsStr(selPkt.tcpFlags)}</span></span>}
                    </div>
                    {selPkt.info&&<div className="text-slate-300">{selPkt.info}</div>}
                    <div className="text-slate-600 leading-relaxed break-all">
                      <span className="text-slate-700">hex: </span>
                      <span className="text-slate-500">{hexLine(selPkt.raw)}</span>
                      {selPkt.raw.length>=128&&<span className="text-slate-700"> … [snaplen 128B]</span>}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
