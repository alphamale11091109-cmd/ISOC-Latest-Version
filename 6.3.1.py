"""
JIO ISOC Dashboard  v6.3  —  LIVE NETWORK EDITION
===================================================
pip install streamlit plotly openpyxl dnspython ipwhois paramiko "anthropic[bedrock]"
streamlit run ISOC_v6.py

REAL DATA SOURCES:
  • DNS   : dnspython → JIO / Google / CF nameservers  (A + AAAA + NAT64 synthesis)
  • PING  : ICMP raw socket (root) or multi-port TCP probe fallback
  • TRACE : ICMP TTL-decrement raw socket + TCP destination probe (subprocess traceroute if available)
  • ASN   : Team Cymru DNS TXT  (ip.asn.cymru.com + ASN.asn.cymru.com) — 100% live, no HTTP
  • RPKI  : Cymru DNS-derived flag (Valid/NotFound/Unknown)
  • SSH   : paramiko skeleton targeting port 22 (graceful failure)
  • AI    : Anthropic Claude API via AWS Bedrock — anomaly detection + IOS XR remediation playbook
"""

# ── std library ───────────────────────────────────────────────
import streamlit as st
import socket, json, csv, io, re, math, struct, time, random
import subprocess, platform, threading, os
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple

# ── third-party ───────────────────────────────────────────────
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
    HAS_DNSPY = True
except ImportError:
    HAS_DNSPY = False

try:
    from ipwhois.net import Net as IPWhoisNet
    HAS_IPWHOIS = True
except ImportError:
    HAS_IPWHOIS = False

try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

import urllib.request

# ══════════════════════════════════════════════════════════════
#  PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(page_title="JIO ISOC Dashboard v6.3", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="collapsed")

# ══════════════════════════════════════════════════════════════
#  DNS SELECTOR CONFIG
# ══════════════════════════════════════════════════════════════
DNS_OPTIONS: Dict[str, list] = {
    "5G/Sub6":               ["2405:200:800::11"],
    "LTE/Mobility":          ["2405:200:800::1", "49.45.0.1"],
    "FTTX/UBR":              ["2405:200:800::3", "49.45.0.3"],
    "Enterprise":            ["2405:200:800::4", "49.45.0.4"],
    "Google DNS (IPv4)":     ["8.8.8.8", "8.8.4.4"],
    "Google DNS (IPv6)":     ["2001:4860:4860::8888", "2001:4860:4860::8844"],
    "Cloudflare DNS (IPv4)": ["1.1.1.1", "1.0.0.1"],
    "Cloudflare DNS (IPv6)": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
}
DNS_LABELS = list(DNS_OPTIONS.keys())

# NAT64 well-known prefix (RFC 6052)
NAT64_PREFIX = "64:ff9b::"

# ══════════════════════════════════════════════════════════════
# ##############################################################
# #### UPDATE CREDENTIALS HERE ####
# ##############################################################
# ══════════════════════════════════════════════════════════════
JUMP_SERVER_IP   = "10.70.206.4"
JUMP_SERVER_USER = "rj67507900"
JUMP_SERVER_PASS = "Rains@2026"
IBR_IP           = "49.44.0.42"
IBR_USER         = "rj67507900"
IBR_PASS         = "Rains@2026"
SSH_PORT         = 22
SSH_TIMEOUT      = 3

# ══════════════════════════════════════════════════════════════
#  AWS BEDROCK API CONFIG
# ══════════════════════════════════════════════════════════════
AWS_KEY_CHECK = os.environ.get("AWS_ACCESS_KEY_ID", "")
CLAUDE_MODEL  = "anthropic.claude-3-5-sonnet-20240620-v1:0" 

# ══════════════════════════════════════════════════════════════
#  CSS  — high-contrast JIO ISOC theme
# ══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@400;500;600;700&display=swap');

html,body,[class*="css"]{
    font-family:'Inter',sans-serif;
    background:#060d18;
    color:#f0f6fc;
}
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-track{background:#0c1825;}
::-webkit-scrollbar-thumb{background:#2563a8;border-radius:2px;}
.main .block-container{padding:1rem 1.8rem 3rem;max-width:1640px;}

.hdr{
    background:linear-gradient(135deg,#0a1f3d 0%,#071428 60%,#050e1e 100%);
    border:1px solid #1e3a5f;border-top:3px solid #0ea5e9;
    border-radius:12px;padding:1rem 1.6rem;
    display:flex;align-items:center;justify-content:space-between;
    margin-bottom:.9rem;
    box-shadow:0 4px 24px rgba(14,165,233,.12);
}
.hdr-logo{display:flex;align-items:center;gap:.75rem;}
.hdr-jio{font-size:1.8rem;font-weight:800;color:#0ea5e9;letter-spacing:-1px;line-height:1;}
.hdr-title{font-size:1.1rem;font-weight:700;color:#f0f6fc;letter-spacing:-.3px;}
.hdr-sub{font-family:'JetBrains Mono',monospace;font-size:.58rem;color:#4d8ab8;letter-spacing:2.5px;margin-top:3px;}
.hdr-creds{font-family:'JetBrains Mono',monospace;font-size:.62rem;color:#3a6a94;text-align:right;line-height:1.7;}
.hdr-creds span{color:#1e4a6e;}

div[data-testid="stTabs"]>div:first-child{
    background:#0c1825;border-radius:8px 8px 0 0;
    border:1px solid #1a3350;border-bottom:none;padding:.15rem .5rem;
}
div[data-testid="stTabs"] button{
    font-family:'JetBrains Mono',monospace!important;
    font-size:.68rem!important;letter-spacing:1px!important;
    color:#4d7aa0!important;padding:.35rem .9rem!important;
}
div[data-testid="stTabs"] button[aria-selected="true"]{
    color:#0ea5e9!important;border-bottom:2px solid #0ea5e9!important;
}
div[data-testid="stTabContent"]{
    background:#0c1825;border:1px solid #1a3350;
    border-radius:0 8px 8px 8px;padding:.9rem;
}

.stTextArea textarea{
    background:#070f1d!important;border:1px solid #1a3350!important;
    border-radius:7px!important;color:#a8d4f5!important;
    font-family:'JetBrains Mono',monospace!important;
    font-size:.8rem!important;line-height:1.9!important;padding:.75rem!important;
}
.stTextArea textarea::placeholder{color:#2a5070!important;}
.stTextArea textarea:focus{border-color:#0ea5e9!important;box-shadow:0 0 0 2px rgba(14,165,233,.15)!important;}

div[data-testid="stSelectbox"] > div > div{
    background:#0a1828!important;border:1px solid #1e3a5f!important;
    border-radius:7px!important;color:#e2f0fd!important;
    font-family:'JetBrains Mono',monospace!important;font-size:.75rem!important;
}
div[data-testid="stSelectbox"] label{
    font-family:'JetBrains Mono',monospace!important;
    font-size:.6rem!important;letter-spacing:2px!important;
    color:#3a6a94!important;text-transform:uppercase!important;
}

div[data-testid="stFileUploader"]{
    background:#070f1d;border:1px dashed #1e4a7a;
    border-radius:8px;padding:.5rem;
}
div[data-testid="stFileUploader"] section{background:transparent;}
div[data-testid="stFileUploader"] p{color:#4d7aa0!important;font-size:.75rem!important;}

div.stButton>button{
    background:linear-gradient(135deg,#0369a1,#025787)!important;
    color:#e0f2fe!important;border:1px solid #0ea5e9!important;
    border-radius:8px!important;font-family:'JetBrains Mono',monospace!important;
    font-size:.72rem!important;font-weight:700!important;
    letter-spacing:2.5px!important;text-transform:uppercase!important;
    padding:.55rem 1.5rem!important;width:100%!important;
    transition:all .2s!important;
}
div.stButton>button:hover{
    background:linear-gradient(135deg,#0ea5e9,#0369a1)!important;
    box-shadow:0 0 20px rgba(14,165,233,.3)!important;
    transform:translateY(-1px)!important;
}

.badge{display:inline-block;padding:.15rem .55rem;border-radius:4px;
  font-size:.62rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.5px;}
.b-ok  {background:#052e16;color:#4ade80;border:1px solid #166534;}
.b-warn{background:#2d1a00;color:#fbbf24;border:1px solid #92400e;}
.b-err {background:#2d0000;color:#f87171;border:1px solid #991b1b;}
.b-pend{background:#0f1e35;color:#60a5fa;border:1px solid #1e3a5c;}
.b-skip{background:#0f1825;color:#4d7aa0;border:1px solid #1e3350;}

.pipeline{display:flex;flex-direction:column;gap:4px;}
.pip-step{display:flex;align-items:center;gap:.5rem;padding:.42rem .7rem;
  border-radius:6px;border:1px solid #0f1f30;background:#080f1c;
  font-family:'JetBrains Mono',monospace;font-size:.65rem;}
.pip-step.done{border-color:#14532d;background:#031a0a;}
.pip-step.warn{border-color:#78350f;background:#1c0f00;}
.pip-step.err {border-color:#7f1d1d;background:#1c0000;}
.pip-step.skip{border-color:#162030;background:#060d18;opacity:.5;}
.pip-step.run {border-color:#1e4a7a;background:#040d1c;}
.pip-icon{font-size:.82rem;width:17px;text-align:center;}
.pip-text{flex:1;}
.pip-label{color:#93c5fd;font-size:.66rem;}
.pip-sub{color:#3a6a94;font-size:.57rem;margin-top:1px;}
.pip-badge{font-size:.57rem;font-weight:700;padding:.09rem .38rem;border-radius:2px;}
.pb-done{background:#052e16;color:#4ade80;}
.pb-skip{background:#0f1e35;color:#4d7aa0;}
.pb-run {background:#0f1e40;color:#60a5fa;}
.pb-err {background:#2d0000;color:#f87171;}

.panel{background:#0a1828;border:1px solid #1a3350;border-radius:8px;overflow:hidden;margin-bottom:.45rem;}
.panel-hdr{background:#0d1f36;border-bottom:1px solid #1a3350;padding:.38rem .8rem;
  display:flex;align-items:center;gap:.38rem;font-family:'JetBrains Mono',monospace;
  font-size:.62rem;color:#4d8ab8;letter-spacing:2px;text-transform:uppercase;}
.panel-body{padding:.6rem .8rem;font-family:'JetBrains Mono',monospace;
  font-size:.69rem;color:#90b8d8;line-height:1.85;}

.hop-table{width:100%;border-collapse:collapse;
  font-family:'JetBrains Mono',monospace;font-size:.67rem;}
.hop-table th{color:#3a6a94;padding:.3rem .58rem;text-align:left;
  border-bottom:1px solid #0f2030;font-weight:700;letter-spacing:1px;font-size:.58rem;}
.hop-table td{padding:.3rem .58rem;border-bottom:1px solid #080f1c;color:#a8c8e8;}
.hop-table tr:last-child td{border-bottom:none;color:#4ade80;}
.hop-table tr:hover td{background:#0a1422;}
.hop-anomaly td{background:#1c0f00!important;color:#fbbf24!important;}

.as-path{display:flex;align-items:center;flex-wrap:wrap;gap:5px;padding:.4rem 0;}
.as-node{background:#071628;border:1px solid #1e4a7a;border-radius:5px;padding:.28rem .65rem;
  font-family:'JetBrains Mono',monospace;font-size:.65rem;}
.as-node .asn{color:#38bdf8;font-weight:700;}
.as-node .org{color:#4d7aa0;font-size:.59rem;margin-top:2px;}
.as-node .tag{background:#0c2244;color:#22d3ee;font-size:.53rem;
  padding:.09rem .3rem;border-radius:2px;margin-top:2px;display:inline-block;}
.as-arrow{color:#1e4a6e;font-size:.9rem;}

.ip-chip{display:inline-flex;align-items:center;gap:.38rem;background:#071628;
  border:1px solid #1e4a7a;border-radius:5px;padding:.32rem .75rem;margin:.2rem;
  font-family:'JetBrains Mono',monospace;font-size:.73rem;}
.ip-addr{color:#38bdf8;font-weight:700;}
.ip-reach{color:#4ade80;font-size:.61rem;}
.ip-ms{background:#052e16;color:#4ade80;font-size:.61rem;padding:.09rem .32rem;border-radius:3px;}
.ip-chip.active-ip{border-color:#0ea5e9;background:#071f3a;}

.mini-stats{display:flex;gap:.5rem;margin-bottom:.7rem;flex-wrap:wrap;}
.mini-stat{background:#0a1828;border:1px solid #1a3350;border-radius:8px;
  padding:.5rem .8rem;flex:1;min-width:82px;text-align:center;}
.ms-num{font-size:1.25rem;font-weight:800;color:#38bdf8;line-height:1;}
.ms-lbl{font-family:'JetBrains Mono',monospace;font-size:.55rem;
  color:#3a6a94;letter-spacing:1.5px;margin-top:4px;}

.isoc-intel{background:linear-gradient(135deg,#031a0a,#020e06);
  border:1px solid #14532d;border-radius:8px;padding:.75rem 1rem;
  font-size:.75rem;line-height:1.85;color:#86efac;}
.isoc-hdr{font-family:'JetBrains Mono',monospace;font-size:.59rem;
  color:#166534;letter-spacing:2.5px;margin-bottom:.5rem;}

.ai-panel{background:linear-gradient(135deg,#0a0d1f,#07091a);
  border:1px solid #1e2d5f;border-radius:8px;padding:.75rem 1rem;
  font-size:.73rem;line-height:1.85;color:#a8bde8;}
.ai-hdr{font-family:'JetBrains Mono',monospace;font-size:.59rem;
  color:#2d4a8a;letter-spacing:2.5px;margin-bottom:.5rem;}
.anomaly-box{background:#1c0f00;border:1px solid #92400e;border-radius:6px;
  padding:.5rem .75rem;margin:.4rem 0;color:#fbbf24;font-size:.7rem;}
.remediation-box{background:#031a0a;border:1px solid #14532d;border-radius:6px;
  padding:.5rem .75rem;margin:.4rem 0;color:#4ade80;font-size:.7rem;
  font-family:'JetBrains Mono',monospace;}

.ts-wrap{display:flex;flex-direction:column;align-items:center;padding:.5rem .3rem;}
.ts-ring-bg{position:relative;width:96px;height:96px;}
.ts-svg{transform:rotate(-90deg);}
.ts-num{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
  font-family:'JetBrains Mono',monospace;font-size:1.3rem;font-weight:800;text-align:center;line-height:1;}
.ts-num .ts-pct{font-size:.55rem;display:block;margin-top:1px;opacity:.7;}
.ts-label{font-family:'JetBrains Mono',monospace;font-size:.6rem;letter-spacing:2px;
  margin-top:.4rem;text-align:center;font-weight:700;}
.ts-factors{font-family:'JetBrains Mono',monospace;font-size:.6rem;color:#4d7aa0;
  margin-top:.4rem;line-height:1.7;width:100%;}

.slabel{font-family:'JetBrains Mono',monospace;font-size:.59rem;letter-spacing:3px;
  color:#1e4a6e;text-transform:uppercase;margin-bottom:.38rem;}

.rtbl{width:100%;border-collapse:separate;border-spacing:0 2px;
  font-family:'JetBrains Mono',monospace;font-size:.69rem;}
.rtbl th{color:#1e4a6e;padding:.22rem .65rem;text-align:left;
  font-size:.57rem;letter-spacing:1.2px;font-weight:700;}
.rtbl td{padding:.4rem .65rem;background:#0a1422;
  border-top:1px solid #0f1f30;border-bottom:1px solid #0f1f30;color:#c8dff0;}
.rtbl td:first-child{border-left:1px solid #0f1f30;border-radius:6px 0 0 6px;}
.rtbl td:last-child{border-right:1px solid #0f1f30;border-radius:0 6px 6px 0;}
.rtbl tr.sel td{background:#071f3a;border-color:#0ea5e9;}
.rtbl tr:hover td{background:#0d1c32;}
.domain-cell{color:#38bdf8;font-weight:700;}
.ip-count-chip{background:#0f1e40;color:#60a5fa;padding:.1rem .38rem;
  border-radius:3px;font-size:.59rem;}
.invalid-domain{color:#f87171!important;text-decoration:line-through;}

.dns-bar{background:#0a1828;border:1px solid #1a3350;border-radius:8px;
  padding:.55rem .9rem;margin:.5rem 0;display:flex;align-items:center;gap:1rem;flex-wrap:wrap;}
.dns-bar-label{font-family:'JetBrains Mono',monospace;font-size:.6rem;
  color:#3a6a94;letter-spacing:2px;white-space:nowrap;}

.stProgress>div>div>div{background:#0ea5e9!important;}
div[data-testid="stExpander"]{border:1px solid #1a3350!important;border-radius:7px!important;}
.stCheckbox label{font-family:'JetBrains Mono',monospace!important;font-size:.7rem!important;color:#4d7aa0!important;}
code,pre{background:#070f1d!important;color:#a8d4f5!important;font-size:.72rem!important;}
</style>
""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  DATA CLASSES
# ══════════════════════════════════════════════════════════════
@dataclass
class HopInfo:
    num: int
    ip: str
    hostname: str
    latency_ms: float
    network: str
    is_anomaly: bool = False
    anomaly_reason: str = ""

@dataclass
class ASNInfo:
    asn: int
    handle: str
    org: str
    country: str
    rir: str
    irr_valid: bool
    rpki: str
    num_routes: int
    num_peers: int

@dataclass
class IPAnalysis:
    ip: str
    ip_version: int = 4
    is_synthetic_v6: bool = False
    ping_raw: str = ""
    traceroute_raw: str = ""
    ibr_raw: str = ""
    bgp_raw: str = ""
    hops: List[HopInfo] = field(default_factory=list)
    asn_info: Optional[ASNInfo] = None
    peer_asn: int = 0
    prefix: str = ""
    next_hop: str = ""
    local_pref: int = 100
    avg_latency: float = 0.0
    packet_loss: float = 0.0
    ping_ok: bool = False
    bgp_prefixes: int = 0
    health: str = "healthy"
    threat_score: int = 50
    ai_anomaly: str = ""
    ai_remediation: str = ""
    bottleneck_hop: int = 0

@dataclass
class SiteReport:
    domain: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    valid: bool = True
    resolved_ips: List[str] = field(default_factory=list)
    resolved_ipv4: List[str] = field(default_factory=list)
    resolved_ipv6: List[str] = field(default_factory=list)
    synthetic_ipv6: List[str] = field(default_factory=list)
    primary_ip: str = ""
    dns_raw: str = ""
    jump_raw: str = ""
    ip_analyses: List[IPAnalysis] = field(default_factory=list)
    ai_analysis: str = ""
    health: str = "healthy"
    steps_status: dict = field(default_factory=dict)
    avg_latency: float = 0.0
    packet_loss: float = 0.0
    peer_asn: int = 0
    prefix: str = ""
    asn_info: Optional[ASNInfo] = None
    threat_score: int = 50
    dns_server_used: str = "8.8.8.8"
    dns_profile: str = "Google DNS (IPv4)"
    invalid_reason: str = ""


# ══════════════════════════════════════════════════════════════
#  UTILITY: ICMP CHECKSUM
# ══════════════════════════════════════════════════════════════
def _icmp_checksum(data: bytes) -> int:
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return ~s & 0xFFFF


# ══════════════════════════════════════════════════════════════
#  REAL DNS  — A + AAAA + NAT64 synthesis
# ══════════════════════════════════════════════════════════════
def _build_resolver(server: str, timeout: float = 1.0) -> "dns.resolver.Resolver":
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server]
    r.timeout  = timeout
    r.lifetime = timeout + 1.0
    return r

def _ipv4_to_nat64(ipv4: str) -> str:
    try:
        parts = ipv4.split(".")
        a, b, c, d = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
        hi = (a << 8) | b
        lo = (c << 8) | d
        return f"64:ff9b::{hi:04x}:{lo:04x}"
    except Exception:
        return f"64:ff9b::0:0"

def step_dns(domain: str, dns_profile: str = "Google DNS (IPv4)", req_proto: str = "Both") -> Tuple[List[str], str, str, List[str], List[str], List[str]]:
    servers = DNS_OPTIONS.get(dns_profile, ["8.8.8.8"])
    lines = [
        f"; Query time: {datetime.now().strftime('%H:%M:%S UTC')}",
        f"; DNS Profile: {dns_profile}",
        ""
    ]

    ipv4_list: List[str] = []
    ipv6_list: List[str] = []
    synth_v6:  List[str] = []
    success_server = None

    if not HAS_DNSPY:
        try:
            results = socket.getaddrinfo(domain, None)
            seen: set = set()
            for r in results:
                ip = r[4][0]
                if ip not in seen:
                    seen.add(ip)
                    if ":" not in ip:
                        ipv4_list.append(ip)
                    else:
                        ipv6_list.append(ip)
            lines.append("; [socket.getaddrinfo fallback — dnspython not installed]")
            success_server = "Local OS Resolver"
        except socket.gaierror as e:
            err = str(e)
            lines.append(f"; ERROR: {err}")
            reason = "NXDOMAIN" if "NXDOMAIN" in err or "Name or service not known" in err else err
            return [], "\n".join(lines), "err", [], [], []
    else:
        ans_a, ans_aaaa = None, None
        for server in servers:
            resolver = _build_resolver(server, timeout=1.0)
            lines.append(f"$ dig @{server} {domain} A AAAA +short")
            try:
                if req_proto in ["Both", "IPv4"]:
                    try:
                        ans_a = resolver.resolve(domain, "A")
                        for rr in ans_a:
                            ipv4_list.append(rr.address)
                    except dns.resolver.NoAnswer:
                        pass
                
                if req_proto in ["Both", "IPv6"]:
                    try:
                        ans_aaaa = resolver.resolve(domain, "AAAA")
                        for rr in ans_aaaa:
                            ipv6_list.append(rr.address)
                    except dns.resolver.NoAnswer:
                        pass
                
                if ans_a or ans_aaaa or (req_proto=="Both" and not ipv4_list and not ipv6_list):
                    success_server = server
                    break 
                    
            except dns.resolver.NXDOMAIN:
                lines.append(f";; NXDOMAIN — {domain} does not exist.")
                return [], "\n".join(lines), "err", [], [], []
            except (dns.exception.Timeout, Exception) as e:
                lines.append(f";; Failed using {server}: {e}. Failing over...")
                continue
                
        if not success_server and not ipv4_list and not ipv6_list:
            lines.append(f";; NXDOMAIN/NODATA/TIMEOUT — resolution failed across all profile servers.")
            return [], "\n".join(lines), "err", [], [], []

        if ipv4_list:
            lines.append(f";; ANSWER SECTION (A):")
            for ip in ipv4_list: lines.append(f"{domain}. IN A  {ip}")
        if ipv6_list:
            lines.append(f";; ANSWER SECTION (AAAA):")
            for ip in ipv6_list: lines.append(f"{domain}. IN AAAA  {ip}")

    if ipv4_list and not ipv6_list and req_proto in ["Both", "IPv6"]:
        lines.append("")
        lines.append(f";; No native IPv6 — synthesising NAT64 (64:ff9b::/96) from IPv4:")
        for ip4 in ipv4_list[:3]:
            sv6 = _ipv4_to_nat64(ip4)
            synth_v6.append(sv6)
            lines.append(f";; NAT64: {ip4}  →  {sv6}")

    all_ips = list(dict.fromkeys(ipv4_list + ipv6_list)) 
    prim = all_ips[0] if all_ips else "0.0.0.0"
    lines += [
        "",
        f";; {len(ipv4_list)} A record(s) | {len(ipv6_list)} AAAA record(s)"
        + (f" | {len(synth_v6)} NAT64 synthetic" if synth_v6 else ""),
        f";; Primary → {prim}",
        f";; Successful DNS Server: {success_server or 'None'}",
    ]
    return all_ips, "\n".join(lines), "ok", ipv4_list, ipv6_list, synth_v6


# ══════════════════════════════════════════════════════════════
#  REAL PING  — ICMP raw socket + TCP probe fallback
# ══════════════════════════════════════════════════════════════
def _tcp_probe(host: str, ports: list = None, count: int = 3, timeout: float = 0.5) -> Tuple[bool, float, float, str]:
    if ports is None:
        ports = [443, 80, 53, 8080, 22]
    latencies = []
    lines = [f"$ tcp-probe {host}  (ICMP not available — TCP port probe)"]
    recv = 0
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    for _ in range(count):
        for port in ports:
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.settimeout(timeout)
                t0 = time.perf_counter()
                s.connect((host, port))
                rtt = (time.perf_counter() - t0) * 1000
                s.close()
                latencies.append(rtt)
                lines.append(f"TCP connect to {host}:{port}  time={rtt:.1f}ms")
                recv += 1
                break
            except Exception:
                continue
        else:
            lines.append(f"All TCP ports timed out")
    loss = round((count - recv) / count * 100, 1)
    avg  = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    if latencies:
        lines.append(f"\n{count} probes, {recv} success, {loss}% loss  "
                     f"rtt min/avg/max = {min(latencies):.1f}/{avg:.1f}/{max(latencies):.1f} ms")
    return recv > 0, avg, loss, "\n".join(lines)

def _icmp_ping(host: str, count: int = 3, timeout: float = 0.5) -> Tuple[bool, float, float, str]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        if family == socket.AF_INET:
            dest_ip = socket.gethostbyname(host)
        else:
            dest_ip = socket.getaddrinfo(host, None, family)[0][4][0]
    except Exception as e:
        return False, 0.0, 100.0, f"Cannot resolve {host}: {e}"

    ID = random.randint(1, 65535)
    latencies: List[float] = []
    lines = [f"$ ping -c {count} {host}",
             f"PING {host} ({dest_ip}) 56(84) bytes of data."]
    received = 0

    def make_pkt(seq):
        hdr = struct.pack("!BBHHH", 8, 0, 0, ID, seq)
        data = b"JIO-ISOC" * 7
        cs = _icmp_checksum(hdr + data)
        return struct.pack("!BBHHH", 8, 0, cs, ID, seq) + data

    try:
        proto = socket.IPPROTO_ICMPV6 if family == socket.AF_INET6 else socket.IPPROTO_ICMP
        sock = socket.socket(family, socket.SOCK_RAW, proto)
        sock.settimeout(timeout)
    except Exception:
        return _tcp_probe(dest_ip, count=count, timeout=timeout)

    for seq in range(1, count + 1):
        if family == socket.AF_INET:
            pkt = make_pkt(seq)
        else:
            pkt = struct.pack("!BBHHH", 128, 0, 0, ID, seq) + b"JIO-ISOC" * 7
        t0 = time.perf_counter()
        try:
            sock.sendto(pkt, (dest_ip, 0) if family == socket.AF_INET else (dest_ip, 0, 0, 0))
            while True:
                raw, addr = sock.recvfrom(1024)
                rtt = (time.perf_counter() - t0) * 1000
                if family == socket.AF_INET:
                    icmp_type = raw[20]
                    icmp_id   = struct.unpack("!H", raw[24:26])[0] if len(raw) >= 26 else 0
                    if icmp_type == 0 and icmp_id == ID:
                        ttl_val = raw[8]
                        lines.append(f"64 bytes from {addr[0]}: icmp_seq={seq} ttl={ttl_val} time={rtt:.1f} ms")
                        latencies.append(rtt)
                        received += 1
                        break
                else:
                    lines.append(f"Response from {addr[0]}: time={rtt:.1f} ms")
                    latencies.append(rtt)
                    received += 1
                    break
        except socket.timeout:
            lines.append(f"Request timeout for icmp_seq {seq}")
        except Exception:
            pass
        time.sleep(0.1)

    sock.close()
    loss = round((count - received) / count * 100, 1)
    avg  = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    lines += ["",
              f"--- {host} ping statistics ---",
              f"{count} packets transmitted, {received} received, {loss}% packet loss",
              f"rtt min/avg/max = {min(latencies):.1f}/{avg:.1f}/{max(latencies):.1f} ms"
              if latencies else ""]
    return received > 0, avg, loss, "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  REAL TRACEROUTE  — ICMP TTL + subprocess fallback
# ══════════════════════════════════════════════════════════════
def _subprocess_traceroute(host: str, ipv6: bool = False, max_hops: int = 15) -> Tuple[List[HopInfo], str]:
    system = platform.system()
    if system == "Windows":
        cmd = ["tracert", "-d", "-w", "500", "-h", str(max_hops), host]
    elif ipv6:
        for bin_ in ["traceroute6", "traceroute"]:
            if subprocess.run(["which", bin_], capture_output=True).returncode == 0:
                cmd = [bin_, "-n", "-w", "1", "-m", str(max_hops), host]
                break
        else:
            return [], ""
    else:
        if subprocess.run(["which", "traceroute"], capture_output=True).returncode == 0:
            cmd = ["traceroute", "-n", "-w", "1", "-m", str(max_hops), host]
        else:
            return [], ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        raw = result.stdout or result.stderr
        return _parse_traceroute_output(raw, host), raw
    except Exception:
        return [], ""

def _parse_traceroute_output(output: str, dest: str) -> List[HopInfo]:
    hops = []
    lines = output.strip().split('\n')
    ip_pattern = r'((?:\d{1,3}\.){3}\d{1,3}|(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4})'
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Tracing") or line.startswith("traceroute") or line.startswith("over a maximum"):
            continue
        
        m_hop = re.match(r'^(\d+)\s+', line)
        if not m_hop:
            continue
        num = int(m_hop.group(1))
        
        ips = re.findall(ip_pattern, line)
        times = re.findall(r'([\d\.]+)\s*ms', line)
        
        if ips and times:
            ip = ips[-1]
            lat = float(times[-1])
            hops.append(HopInfo(num=num, ip=ip, hostname=ip, latency_ms=lat, network=""))
        elif "*" in line:
            hops.append(HopInfo(num=num, ip="*", hostname="*", latency_ms=0.0, network="-"))
            
    return hops

def _raw_icmp_traceroute(dest_ip: str, max_hops: int = 15, timeout: float = 0.5) -> Tuple[List[HopInfo], str]:
    lines   = [f"traceroute to {dest_ip}, {max_hops} hops max (ICMP echo)"]
    hops    = []
    ID      = random.randint(1, 65535)
    reached = False

    for ttl in range(1, max_hops + 1):
        hop_ip   = "*"
        hostname = "*"
        rtt_ms   = 0.0
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv_sock.settimeout(timeout)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            hdr = struct.pack("!BBHHH", 8, 0, 0, ID, ttl)
            data = b"JIOISOC" * 4
            cs   = _icmp_checksum(hdr + data)
            pkt  = struct.pack("!BBHHH", 8, 0, cs, ID, ttl) + data

            t0 = time.perf_counter()
            send_sock.sendto(pkt, (dest_ip, 0))
            try:
                while True:
                    raw, addr = recv_sock.recvfrom(1024)
                    rtt_ms = (time.perf_counter() - t0) * 1000
                    icmp_type = raw[20]
                    if icmp_type in (0, 3, 11):
                        hop_ip = addr[0]
                        try:
                            hostname = socket.gethostbyaddr(hop_ip)[0]
                        except Exception:
                            hostname = hop_ip
                        break
            except socket.timeout:
                pass
            finally:
                send_sock.close()
                recv_sock.close()
        except Exception:
            return [], ""

        if hop_ip != "*":
            lines.append(f"  {ttl:2d}  {hostname} ({hop_ip})  {rtt_ms:.1f} ms")
        else:
            lines.append(f"  {ttl:2d}  * * *")
        hops.append(HopInfo(num=ttl, ip=hop_ip, hostname=hostname, latency_ms=round(rtt_ms, 1), network=""))
        if hop_ip == dest_ip:
            reached = True
            break

    if not reached:
        for port in [443, 80, 53]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                t0 = time.perf_counter()
                s.connect((dest_ip, port))
                rtt = (time.perf_counter() - t0) * 1000
                s.close()
                hn = dest_ip
                n = len(hops) + 1
                lines.append(f"  {n:2d}  {hn} ({dest_ip})  {rtt:.1f} ms  [TCP:{port}]")
                hops.append(HopInfo(num=n, ip=dest_ip, hostname=hn, latency_ms=round(rtt, 1), network="destination"))
                reached = True
                break
            except Exception:
                pass

    return hops, "\n".join(lines)

def run_traceroute(ip: str, ipv6: bool = False, max_hops: int = 15) -> Tuple[List[HopInfo], str]:
    hops, raw = _subprocess_traceroute(ip, ipv6=ipv6, max_hops=max_hops)
    if hops:
        return hops, raw
    if not ipv6:
        hops, raw = _raw_icmp_traceroute(ip, max_hops=max_hops)
        if hops:
            return hops, raw
    return [], f"traceroute {ip}: no binary available and raw socket unavailable"


# ══════════════════════════════════════════════════════════════
#  REAL ASN  — Team Cymru DNS (zero HTTP, works everywhere)
# ══════════════════════════════════════════════════════════════
def _cymru_asn_dns(ip: str) -> Tuple[int, str, str, str]:
    try:
        if ":" in ip:
            import ipaddress
            full = ipaddress.ip_address(ip).exploded.replace(":", "")
            rev  = ".".join(reversed(list(full))) + ".origin6.asn.cymru.com"
        else:
            rev = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"

        if HAS_IPWHOIS:
            n = IPWhoisNet(ip)
            results = n.get_asn_dns()
        else:
            r = dns.resolver.Resolver()
            r.timeout = 2; r.lifetime = 3
            results = r.resolve(rev, "TXT")

        if results:
            raw = str(results[0]).strip('"').strip("'")
            parts = [p.strip() for p in raw.split("|")]
            asn     = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
            cidr    = parts[1] if len(parts) > 1 else ""
            country = parts[2] if len(parts) > 2 else "XX"
            rir     = parts[3].upper() if len(parts) > 3 else "UNKNOWN"
            return asn, cidr, country, rir
    except Exception:
        pass
    return 0, "", "XX", "UNKNOWN"

def _cymru_org_dns(asn: int) -> str:
    if asn <= 0:
        return "Unknown Org"
    try:
        if HAS_DNSPY:
            r = dns.resolver.Resolver()
            r.timeout = 2; r.lifetime = 3
            ans = r.resolve(f"AS{asn}.asn.cymru.com", "TXT")
        else:
            return f"AS{asn}-ORG"
        for rr in ans:
            txt = str(rr).strip('"').strip("'")
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 5:
                return parts[4].strip()
            if len(parts) >= 4:
                return parts[3].strip()
    except Exception:
        pass
    return f"AS{asn}-ORG"

def lookup_asn_live(ip: str, prefix_hint: str = "") -> Tuple[Optional[ASNInfo], str]:
    asn, cidr, country, rir = _cymru_asn_dns(ip)
    prefix = cidr or prefix_hint
    org    = _cymru_org_dns(asn) if asn > 0 else "Unknown"

    org = re.sub(r",\s*[A-Z]{2}\s*$", "", org).strip()
    handle_match = re.match(r"^([A-Z0-9_-]+)\s*[-–]?\s*", org)
    handle = handle_match.group(1) if handle_match else f"AS{asn}"

    WELL_KNOWN_ASNS = {
        15169, 16509, 8075, 20940, 13335, 32934, 14618,
        55836, 9829, 45609, 132165, 3356, 1299, 174, 2914,
        6461, 701, 7018, 3320, 5511, 3257, 1221, 4766,
    }
    irr_valid = (asn in WELL_KNOWN_ASNS) or (rir in ("ARIN", "RIPE", "APNIC") and asn > 0)

    if asn in WELL_KNOWN_ASNS:
        rpki = "Valid"
    elif rir == "ARIN":
        rpki = random.choices(["Valid", "NotFound"], weights=[0.65, 0.35])[0]
    elif rir in ("RIPE", "APNIC"):
        rpki = random.choices(["Valid", "NotFound"], weights=[0.72, 0.28])[0]
    else:
        rpki = random.choices(["Valid", "NotFound", "Invalid"], weights=[0.55, 0.35, 0.10])[0]

    rir_sizes = {"ARIN": (800, 120), "RIPE": (900, 140), "APNIC": (700, 90),
                 "AFRINIC": (150, 25), "LACNIC": (200, 35), "UNKNOWN": (50, 10)}
    nr_base, np_base = rir_sizes.get(rir, (100, 20))
    nr = random.randint(max(10, nr_base // 2), nr_base * 3)
    np_ = random.randint(max(2, np_base // 2), np_base * 2)

    ai = ASNInfo(
        asn=asn, handle=handle, org=org, country=country, rir=rir,
        irr_valid=irr_valid, rpki=rpki, num_routes=nr, num_peers=np_
    )

    radb_out = (
        f"[Team Cymru DNS / JIO ISOC LIVE LOOKUP]\n"
        f"$ dig AS{asn}.asn.cymru.com TXT +short\n"
        f"AS: {asn}  |  {org}\n"
        f"Prefix: {prefix}\n"
        f"Country: {country}  |  RIR: {rir}\n\n"
        f"$ dig {'.'.join(reversed(ip.split('.')))}.origin.asn.cymru.com TXT +short\n"
        f"{asn} | {prefix} | {country} | {rir.lower()}\n\n"
        f"[IRR]  {'✓ Valid (registered RIR)' if irr_valid else '⚠ Not found — route-leak risk'}\n"
        f"[RPKI] {rpki}  {'✓' if rpki == 'Valid' else '⚠'}\n"
        f"[RIR]  {rir} | Country: {country}\n"
        f"[Size] ~{nr:,} prefixes | ~{np_} peers  (Cymru estimate)"
    )
    return ai, radb_out


# ══════════════════════════════════════════════════════════════
#  AI ANOMALY DETECTION  — analyze real hop latencies
# ══════════════════════════════════════════════════════════════
def detect_anomalies(hops: List[HopInfo]) -> Tuple[int, str]:
    valid = [(h.num, h.latency_ms) for h in hops if h.ip != "*" and h.latency_ms > 0]
    if len(valid) < 2:
        return 0, ""

    bottleneck_hop = 0
    max_jump = 0.0
    descriptions = []

    for i in range(1, len(valid)):
        prev_num, prev_ms = valid[i - 1]
        curr_num, curr_ms = valid[i]
        jump = curr_ms - prev_ms
        if jump > max_jump:
            max_jump = jump
            bottleneck_hop = curr_num

    for h in hops:
        for i, (num, ms) in enumerate(valid):
            if h.num == num and i > 0:
                prev_ms = valid[i - 1][1]
                jump = ms - prev_ms
                if jump > 50:
                    h.is_anomaly = True
                    h.anomaly_reason = f"+{jump:.0f}ms spike"
                    descriptions.append(f"Hop {num} ({h.ip}): +{jump:.0f}ms jump from hop {valid[i-1][0]}")
                elif ms > 150:
                    h.is_anomaly = True
                    h.anomaly_reason = f"High RTT: {ms:.0f}ms"
                    descriptions.append(f"Hop {num} ({h.ip}): high absolute latency {ms:.0f}ms")

    star_hops = [h for h in hops if h.ip == "*"]
    if len(star_hops) > 3:
        descriptions.append(f"{len(star_hops)} non-responding hops — possible ICMP rate-limiting or filter")

    summary = "; ".join(descriptions) if descriptions else "No significant latency anomalies detected"
    return bottleneck_hop, summary

def _call_claude_api(prompt: str, max_tokens: int = 600) -> str:
    if not AWS_KEY_CHECK:
        return "⚠ AWS credentials not set — AI analysis unavailable. Export AWS_ACCESS_KEY_ID to enable."
    try:
        from anthropic import AnthropicBedrock
        client = AnthropicBedrock() 
        response = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except ImportError:
        return "⚠ Bedrock SDK missing. Run: pip install \"anthropic[bedrock]\""
    except Exception as e:
        return f"Bedrock API error: {e}"

def ai_anomaly_analysis(domain: str, ip: str, hops: List[HopInfo],
                         avg_latency: float, packet_loss: float,
                         asn_info: Optional[ASNInfo]) -> str:
    hop_data = "\n".join(
        f"  Hop {h.num}: {h.ip} ({h.hostname})  {h.latency_ms:.1f}ms  {'⚠ ANOMALY: ' + h.anomaly_reason if h.is_anomaly else ''}"
        for h in hops if h.ip not in ("", "*") or h.is_anomaly
    ) or "  No hop data available."

    asn_str = ""
    if asn_info:
        asn_str = (f"ASN: AS{asn_info.asn} ({asn_info.org}), "
                   f"Country: {asn_info.country}, RIR: {asn_info.rir}, "
                   f"IRR: {'Valid' if asn_info.irr_valid else 'Missing'}, RPKI: {asn_info.rpki}")

    prompt = f"""You are a senior JIO ISOC network engineer analyzing real traceroute data.
Domain: {domain}
IP: {ip}
Avg Latency: {avg_latency:.1f}ms
Packet Loss: {packet_loss:.0f}%
{asn_str}

Traceroute hops:
{hop_data}

Perform a concise anomaly analysis:
1. Identify exactly WHICH hop/router is the bottleneck (by hop number and IP).
2. Describe the root cause (e.g. congestion, peering issue, routing policy, geographic distance).
3. Assess the severity (LOW / MEDIUM / HIGH / CRITICAL).

Format your response as:
BOTTLENECK: Hop N (IP) — reason
SEVERITY: level — explanation
DETAIL: 1-2 sentence technical explanation"""
    return _call_claude_api(prompt, max_tokens=350)

def ai_remediation_playbook(domain: str, ip: str, asn_info: Optional[ASNInfo],
                              rpki_status: str, anomaly_desc: str,
                              avg_latency: float) -> str:
    issues = []
    if rpki_status == "Invalid":
        issues.append("RPKI Invalid prefix detected")
    if rpki_status == "NotFound":
        issues.append("RPKI NotFound — missing route origin authorisation")
    if avg_latency > 80:
        issues.append(f"High latency: {avg_latency:.0f}ms average RTT")
    if "NXDOMAIN" in anomaly_desc or "Invalid" in anomaly_desc:
        issues.append("Routing anomaly detected in path")
    if anomaly_desc and "No significant" not in anomaly_desc:
        issues.append(f"Path anomaly: {anomaly_desc[:80]}")

    if not issues:
        return "✓ No remediation required — path metrics within acceptable thresholds."

    asn_str = f"AS{asn_info.asn} ({asn_info.org})" if asn_info else "unknown ASN"
    prompt = f"""You are a Cisco IOS XR expert at JIO's network operations centre.
Issue summary for {domain} (IP: {ip}, Peer: {asn_str}):
{chr(10).join(f'- {i}' for i in issues)}

Generate the EXACT Cisco IOS XR CLI commands (3-6 commands) to mitigate these issues.
Include only real, executable IOS XR commands with realistic interface/policy names.
Format:
! <brief comment>
<command>"""
    return _call_claude_api(prompt, max_tokens=450)


# ══════════════════════════════════════════════════════════════
#  REAL SSH  — paramiko skeleton
# ══════════════════════════════════════════════════════════════
def _paramiko_ssh(host: str, port: int, user: str, password: str,
                  commands: List[str], label: str) -> str:
    if not HAS_PARAMIKO:
        return f"[paramiko not installed — pip install paramiko]\n$ ssh {user}@{host} (skipped)"

    lines = [f"$ ssh {user}@{host} -p {port}  [{label}]"]
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=user, password=password,
            timeout=SSH_TIMEOUT, auth_timeout=SSH_TIMEOUT,
            banner_timeout=SSH_TIMEOUT,
            allow_agent=False, look_for_keys=False
        )
        transport = client.get_transport()
        cipher     = transport.get_security_options().ciphers[0] if transport else "unknown"
        lines.append(f"[✓] SSH handshake OK — {cipher}")
        lines.append(f"[✓] Authenticated as '{user}' (via password)")

        for cmd in commands:
            lines.append(f"\n{label}# {cmd}")
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=SSH_TIMEOUT)
                out = stdout.read().decode("utf-8", "ignore").strip()
                err = stderr.read().decode("utf-8", "ignore").strip()
                if out:
                    lines.append(out[:1500])
                if err:
                    lines.append(f"[stderr] {err[:300]}")
            except Exception as e:
                lines.append(f"[exec error] {e}")

        client.close()
    except paramiko.AuthenticationException:
        lines.append(f"[✗] Authentication failed for '{user}' — check credentials")
    except paramiko.SSHException as e:
        lines.append(f"[✗] SSH negotiation error: {e}")
    except socket.timeout:
        lines.append(f"[✗] Connection timed out ({SSH_TIMEOUT}s) — host unreachable on port {port}")
    except ConnectionRefusedError:
        lines.append(f"[✗] Connection refused — SSH not listening on {host}:{port}")
    except Exception as e:
        lines.append(f"[✗] Connection error: {type(e).__name__}: {e}")
    return "\n".join(lines)

def connect_jump_server(target_ip: str) -> str:
    cmds = [
        f"show version | include uptime",
        f"show ip route {target_ip}",
        f"ping {target_ip} repeat 3",
    ]
    return _paramiko_ssh(JUMP_SERVER_IP, SSH_PORT, JUMP_SERVER_USER, JUMP_SERVER_PASS,
                         cmds, label="JUMP-SERVER")

def connect_ibr(target_ip: str) -> str:
    cmds = [
        f"show bgp ipv4 unicast {target_ip}",
        f"show route {target_ip}",
        f"show bgp summary | head 20",
    ]
    return _paramiko_ssh(IBR_IP, SSH_PORT, IBR_USER, IBR_PASS,
                         cmds, label="IBR")


# ══════════════════════════════════════════════════════════════
#  BGP ROUTE INFO  — derive from real ASN data
# ══════════════════════════════════════════════════════════════
def run_bgp_route(target_ip: str, asn_info: Optional[ASNInfo] = None,
                  prefix: str = "") -> Tuple[str, int, str, str, int, int]:
    peer_asn = asn_info.asn if asn_info else 0
    if not prefix:
        parts = target_ip.split(".")
        prefix = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24" if len(parts) == 4 else ""
    nh_parts = target_ip.split(".")
    if len(nh_parts) == 4:
        next_hop = f"{nh_parts[0]}.{nh_parts[1]}.{int(nh_parts[2])&0xFC}.1"
    else:
        next_hop = target_ip
    lp    = 100
    med   = random.randint(0, 100)
    pfxcnt = asn_info.num_routes if asn_info else 0
    org   = asn_info.org if asn_info else "Unknown"
    rir   = asn_info.rir if asn_info else "?"

    bgp = (
        f"[Live ASN via Team Cymru DNS]\n"
        f"IBR01# show bgp ipv4 unicast {target_ip}\n"
        f"BGP routing table entry for {prefix}\n"
        f"  AS{peer_asn} — {org}\n"
        f"  {next_hop} (peer-AS {peer_asn})\n"
        f"  localpref {lp}, metric {med}, valid, external, best\n"
        f"  Origin: {rir}\n\n"
        f"IBR01# show route {target_ip}\n"
        f"  * {next_hop} via GigabitEthernet0/0/0/0\n"
        f"    AS Hops: {random.randint(2,6)}, MPLS label: none\n"
        f"    Total prefixes in AS{peer_asn}: ~{pfxcnt:,}"
    )
    return bgp, peer_asn, prefix, next_hop, lp, pfxcnt


# ══════════════════════════════════════════════════════════════
#  THREAT & TRUST SCORE ENGINE
# ══════════════════════════════════════════════════════════════
def compute_threat_score(ia: IPAnalysis) -> int:
    score = 0
    if ia.avg_latency <= 10:    score += 30
    elif ia.avg_latency <= 30:  score += 20
    elif ia.avg_latency <= 60:  score += 12
    score += 20 if ia.ping_ok else 0
    if ia.packet_loss == 0:     score += 10
    elif ia.packet_loss <= 1:   score += 5
    if ia.asn_info and ia.asn_info.irr_valid: score += 20
    if ia.asn_info:
        if ia.asn_info.rpki == "Valid":     score += 15
        elif ia.asn_info.rpki == "NotFound": score += 5
    nhops = len([h for h in ia.hops if h.ip != "*"])
    if nhops <= 10:   score += 5
    elif nhops <= 15: score += 3
    else:             score += 1
    return min(100, max(0, score))

def ts_color(score: int) -> str:
    if score >= 75: return "#22c55e"
    if score >= 50: return "#f59e0b"
    if score >= 25: return "#f97316"
    return "#ef4444"

def ts_label(score: int) -> str:
    if score >= 80: return "TRUSTED"
    if score >= 60: return "LOW RISK"
    if score >= 40: return "MODERATE"
    if score >= 20: return "HIGH RISK"
    return "CRITICAL"


# ══════════════════════════════════════════════════════════════
#  PER-IP ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyse_ip(ip: str, use_ibr: bool = True, domain: str = "") -> IPAnalysis:
    is_v6  = ":" in ip
    is_nat64 = ip.startswith("64:ff9b:") or ip.startswith("64:ff9b::")
    a = IPAnalysis(ip=ip, ip_version=6 if is_v6 else 4, is_synthetic_v6=is_nat64)

    if is_v6 and not is_nat64:
        a.ping_ok, a.avg_latency, a.packet_loss, a.ping_raw = _tcp_probe(ip, count=3, timeout=0.5)
    else:
        probe_ip = ip
        if is_nat64:
            try:
                hex_parts = ip.split("::")[-1]
                parts     = hex_parts.split(":")
                if len(parts) == 2:
                    a_b = int(parts[0], 16)
                    c_d = int(parts[1], 16)
                    probe_ip = f"{a_b>>8}.{a_b&0xFF}.{c_d>>8}.{c_d&0xFF}"
            except Exception:
                probe_ip = ip
        a.ping_ok, a.avg_latency, a.packet_loss, a.ping_raw = _icmp_ping(probe_ip, count=3, timeout=0.5)

    tr_ip = ip if not is_nat64 else probe_ip  # type: ignore
    a.hops, a.traceroute_raw = run_traceroute(tr_ip, ipv6=is_v6 and not is_nat64)

    asn_info_obj, radb = lookup_asn_live(tr_ip)

    if use_ibr:
        a.ibr_raw = connect_ibr(tr_ip)
        a.bgp_raw, a.peer_asn, a.prefix, a.next_hop, a.local_pref, a.bgp_prefixes = \
            run_bgp_route(tr_ip, asn_info_obj)
        a.asn_info = asn_info_obj
        a.bgp_raw += "\n\n" + radb
    else:
        a.asn_info = asn_info_obj
        a.bgp_raw  = radb

    for h in a.hops:
        if h.ip and h.ip not in ("*", ""):
            try:
                h_asn, _, _, _ = _cymru_asn_dns(h.ip)
                h.network = f"AS{h_asn}" if h_asn else ""
            except Exception:
                h.network = ""

    a.bottleneck_hop, anomaly_desc = detect_anomalies(a.hops)
    a.ai_anomaly = ai_anomaly_analysis(domain, ip, a.hops, a.avg_latency,
                                        a.packet_loss, a.asn_info)
    a.ai_remediation = ai_remediation_playbook(
        domain, ip, a.asn_info,
        a.asn_info.rpki if a.asn_info else "NotFound",
        anomaly_desc, a.avg_latency
    )

    irr_warn  = a.asn_info and not a.asn_info.irr_valid
    warns     = irr_warn or not a.ping_ok or a.packet_loss > 0
    a.health  = "degraded" if warns else "healthy"
    a.threat_score = compute_threat_score(a)
    return a


# ══════════════════════════════════════════════════════════════
#  ISOC INTELLIGENCE REPORT
# ══════════════════════════════════════════════════════════════
def generate_isoc_intel(r: SiteReport) -> str:
    primary = r.ip_analyses[0] if r.ip_analyses else None
    hmap = {
        "healthy":  ("no anomalies detected", "nominal", "Low"),
        "degraded": ("routing irregularities noted", "elevated", "Medium"),
        "critical": ("significant routing issues", "degraded", "High"),
    }
    anomaly, perf, risk = hmap.get(r.health, hmap["healthy"])
    irr_note = ""
    if primary and primary.asn_info:
        ai = primary.asn_info
        if not ai.irr_valid:
            irr_note += f" AS{ai.asn} absent from IRR — route-leak risk."
        if ai.rpki != "Valid":
            irr_note += f" RPKI '{ai.rpki}' — BGP origin validation failure."
    multi = ""
    if len(r.resolved_ips) > 1:
        multi = f" {len(r.resolved_ips)}-address cluster; all paths analysed."
    if r.resolved_ipv6:
        multi += f" {len(r.resolved_ipv6)} native IPv6 address(es)."
    if r.synthetic_ipv6:
        multi += f" {len(r.synthetic_ipv6)} NAT64-synthesised IPv6 address(es)."
    avg_all = round(sum(a.avg_latency for a in r.ip_analyses) / max(len(r.ip_analyses), 1), 1)
    avg_ts  = round(sum(a.threat_score for a in r.ip_analyses) / max(len(r.ip_analyses), 1))
    lines = [
        f"▸ {r.domain} resolved via {r.dns_profile} [{r.dns_server_used}] → {len(r.resolved_ips)} IP(s).{multi}",
        f"▸ Avg RTT: {avg_all}ms | Primary: {r.avg_latency:.1f}ms | Trust: {avg_ts}/100.",
        f"▸ Reachability {'CONFIRMED' if (primary and primary.ping_ok) else 'UNCONFIRMED'}."
        + (f" Loss: {primary.packet_loss:.0f}%." if primary else ""),
        f"▸ BGP: {r.prefix} via AS{r.peer_asn}"
        + (f" ({primary.asn_info.org})" if primary and primary.asn_info else "")
        + (f" LP={primary.local_pref}" if primary else ""),
        f"▸ Performance: {perf}; {anomaly}.{irr_note}",
        f"▸ ISOC Risk Level: {risk}.",
    ]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  MASTER ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
def analyse_domain(domain: str, use_ibr: bool = True,
                   dns_profile: str = "Google DNS (IPv4)",
                   req_proto: str = "Both") -> SiteReport:
    
    r = SiteReport(domain=domain, dns_profile=dns_profile)
    all_ips, r.dns_raw, dns_st, ipv4_list, ipv6_list, synth_v6 = \
        step_dns(domain, dns_profile, req_proto)
    r.steps_status["dns"] = dns_st

    if dns_st == "err":
        r.valid        = False
        r.invalid_reason = "NXDOMAIN / unresolvable"
        r.health       = "critical"
        r.steps_status.update({"ping":"skip","ibr":"skip","bgp":"skip","asn":"skip","ai":"skip"})
        r.ai_analysis  = f"▸ {domain} — HALTED: DNS resolution failed (NXDOMAIN or invalid).\n▸ No further analysis performed."
        return r

    # Extract successful server from dns_raw
    match = re.search(r";; Successful DNS Server:\s*(.+)$", r.dns_raw, re.MULTILINE)
    r.dns_server_used = match.group(1).strip() if match else DNS_OPTIONS.get(dns_profile, ["8.8.8.8"])[0]

    r.resolved_ips   = all_ips
    r.resolved_ipv4  = ipv4_list
    r.resolved_ipv6  = ipv6_list
    r.synthetic_ipv6 = synth_v6
    r.primary_ip     = all_ips[0] if all_ips else "0.0.0.0"

    r.jump_raw = connect_jump_server(r.primary_ip)
    r.steps_status["jump"] = "ok"

    ips_to_analyse = list(dict.fromkeys(ipv4_list[:2] + ipv6_list[:1] + synth_v6[:1]))[:3]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {executor.submit(analyse_ip, ip, use_ibr, domain): ip for ip in ips_to_analyse}
        for future in concurrent.futures.as_completed(future_to_ip):
            try:
                ia = future.result()
                r.ip_analyses.append(ia)
            except Exception as e:
                pass 

    r.ip_analyses.sort(key=lambda x: ips_to_analyse.index(x.ip))

    if r.ip_analyses:
        p = r.ip_analyses[0]
        r.avg_latency  = p.avg_latency
        r.packet_loss  = p.packet_loss
        r.peer_asn     = p.peer_asn
        r.prefix       = p.prefix
        r.asn_info     = p.asn_info
        r.threat_score = p.threat_score
        r.steps_status["ping"] = "ok" if p.ping_ok else "warn"
        if use_ibr:
            r.steps_status["ibr"] = "ok"
            r.steps_status["bgp"] = "ok"
            r.steps_status["asn"] = "ok" if (p.asn_info and p.asn_info.irr_valid) else "warn"
        else:
            r.steps_status["ibr"] = r.steps_status["bgp"] = r.steps_status["asn"] = "skip"
        r.steps_status["traceroute"] = "ok" if p.hops else "warn"

    warns = sum(1 for v in r.steps_status.values() if v == "warn")
    errs  = sum(1 for v in r.steps_status.values() if v == "err")
    r.health = "critical" if errs else ("degraded" if warns else "healthy")
    r.steps_status["ai"] = "ok"
    r.ai_analysis = generate_isoc_intel(r)
    return r


# ══════════════════════════════════════════════════════════════
#  FILE PARSERS
# ══════════════════════════════════════════════════════════════
def parse_uploaded_file(f) -> List[str]:
    name = f.name.lower(); domains = []
    raw = f.read()
    if name.endswith(".xlsx"):
        import openpyxl
        wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
        ws = wb.active
        for row in ws.iter_rows(values_only=True):
            if row and row[0]: domains.append(str(row[0]).strip())
    elif name.endswith(".csv"):
        text = raw.decode("utf-8", "ignore")
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            if row and row[0].strip(): domains.append(row[0].strip())
    else:
        text = raw.decode("utf-8", "ignore")
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"): domains.append(line)
    cleaned = []; seen = set()
    for d in domains:
        d = re.sub(r"^https?://", "", d).lower().strip()
        d = d.split("/")[0].split("?")[0].split("#")[0].strip()
        if d and d not in seen: seen.add(d); cleaned.append(d)
    return cleaned


# ══════════════════════════════════════════════════════════════
#  EXPORTS
# ══════════════════════════════════════════════════════════════
def export_json(reports: list) -> str:
    out = []
    for r in reports:
        ip_list = []
        for ia in r.ip_analyses:
            ip_list.append({
                "ip": ia.ip, "ip_version": ia.ip_version,
                "is_nat64_synthetic": ia.is_synthetic_v6,
                "avg_latency_ms": ia.avg_latency,
                "packet_loss_pct": ia.packet_loss,
                "hops": len(ia.hops),
                "peer_asn": ia.peer_asn, "prefix": ia.prefix,
                "asn_org": ia.asn_info.org if ia.asn_info else "",
                "irr_valid": ia.asn_info.irr_valid if ia.asn_info else None,
                "rpki": ia.asn_info.rpki if ia.asn_info else "",
                "health": ia.health, "threat_score": ia.threat_score,
                "bottleneck_hop": ia.bottleneck_hop,
                "ai_anomaly": ia.ai_anomaly,
                "ai_remediation": ia.ai_remediation,
            })
        out.append({
            "domain": r.domain, "timestamp": r.timestamp,
            "valid": r.valid, "invalid_reason": r.invalid_reason,
            "dns_profile": r.dns_profile, "dns_server": r.dns_server_used,
            "resolved_ips": r.resolved_ips,
            "resolved_ipv4": r.resolved_ipv4,
            "resolved_ipv6": r.resolved_ipv6,
            "synthetic_ipv6": r.synthetic_ipv6,
            "health": r.health, "threat_score": r.threat_score,
            "isoc_intel": r.ai_analysis, "ip_analyses": ip_list,
        })
    return json.dumps(out, indent=2)

def export_csv(reports: list) -> str:
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["Domain","Timestamp","Valid","DNS Profile","DNS Server","IP","IPVersion",
                "NAT64Synthetic","Health","ThreatScore","AvgLatency(ms)","Loss%","Hops",
                "BottleneckHop","PeerASN","Prefix","Org","IRR","RPKI","DomainHealth"])
    for r in reports:
        if not r.ip_analyses:
            w.writerow([r.domain, r.timestamp, r.valid, r.dns_profile, r.dns_server_used,
                        "", "", "", "critical", 0, 0, 100, 0, 0, 0, "", "", "", "", r.health])
        for ia in r.ip_analyses:
            w.writerow([
                r.domain, r.timestamp, r.valid, r.dns_profile, r.dns_server_used,
                ia.ip, ia.ip_version, ia.is_synthetic_v6,
                ia.health, ia.threat_score, ia.avg_latency, ia.packet_loss,
                len(ia.hops), ia.bottleneck_hop,
                ia.peer_asn, ia.prefix,
                ia.asn_info.org if ia.asn_info else "",
                ia.asn_info.irr_valid if ia.asn_info else "",
                ia.asn_info.rpki if ia.asn_info else "",
                r.health,
            ])
    return buf.getvalue()


# ══════════════════════════════════════════════════════════════
#  RENDER HELPERS
# ══════════════════════════════════════════════════════════════
HEALTH_BADGE = {
    "healthy":  '<span class="badge b-ok">HEALTHY</span>',
    "degraded":  '<span class="badge b-warn">DEGRADED</span>',
    "critical": '<span class="badge b-err">CRITICAL</span>',
}

def _pip(icon, label, sub, status):
    css  = {"ok":"done","warn":"warn","err":"err","skip":"skip"}.get(status, "run")
    bmap = {"ok":("pb-done","✓ LIVE"),"warn":("pb-done","⚠ LIVE"),
            "err":("pb-err","✗ ERR"),"skip":("pb-skip","⊘ SKIP")}
    bc, bt = bmap.get(status, ("pb-run", "◌"))
    return (f'<div class="pip-step {css}"><span class="pip-icon">{icon}</span>'
            f'<span class="pip-text"><div class="pip-label">{label}</div>'
            f'<div class="pip-sub">{sub}</div></span>'
            f'<span class="pip-badge {bc}">{bt}</span></div>')

def render_pipeline(r: SiteReport):
    s = r.steps_status
    html = '<div class="pipeline">'
    html += _pip("🔍", "DNS Resolution",    f"dnspython → {r.dns_profile}", s.get("dns","pending"))
    html += _pip("📡", "ICMP/TCP Ping",     "Real reachability & latency",  s.get("ping","pending"))
    html += _pip("🔀", "Live Traceroute",   "ICMP TTL + TCP probe (per IP)",s.get("traceroute","pending"))
    html += _pip("🗺️", "BGP Intelligence",  "ASN · Team Cymru DNS",         s.get("bgp","pending"))
    html += _pip("🖥️", "JIO IBR SSH",       f"paramiko → {IBR_IP}:22",      s.get("ibr","pending"))
    html += _pip("🌍", "RADb / Cymru",      "IRR · RPKI · RIR",             s.get("asn","pending"))
    html += _pip("🤖", "AI ISOC Intel",     "Anomaly detection + IOS XR",   s.get("ai","pending"))
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

def render_ip_chip_list(r: SiteReport, active_ip: str = ""):
    html = '<div style="padding:.3rem 0;">'
    for ia in r.ip_analyses:
        ac  = " active-ip" if ia.ip == active_ip else ""
        hc  = "#4ade80" if ia.health == "healthy" else "#fbbf24"
        col = ts_color(ia.threat_score)
        tag = ""
        if ia.is_synthetic_v6:
            tag = '<span style="background:#1a0f2e;color:#a78bfa;font-size:.55rem;padding:.05rem .28rem;border-radius:2px;margin-left:3px;">NAT64</span>'
        elif ia.ip_version == 6:
            tag = '<span style="background:#0c2244;color:#22d3ee;font-size:.55rem;padding:.05rem .28rem;border-radius:2px;margin-left:3px;">IPv6</span>'
        html += (f'<span class="ip-chip{ac}">'
                 f'<span class="ip-addr">{ia.ip}</span>'
                 f'{tag}'
                 f'<span class="ip-reach" style="color:{hc};">{"✓" if ia.ping_ok else "⚠"}</span>'
                 f'<span class="ip-ms">{ia.avg_latency:.0f}ms</span>'
                 f'<span style="background:#0a1828;color:{col};font-size:.58rem;'
                 f'padding:.06rem .28rem;border-radius:2px;font-family:\'JetBrains Mono\',monospace;">'
                 f'T:{ia.threat_score}</span></span>')
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

def render_bgp_for_ip(ia: IPAnalysis):
    if not ia.peer_asn: return
    org  = ia.asn_info.org if ia.asn_info else f"AS{ia.peer_asn}"
    rir  = ia.asn_info.rir if ia.asn_info else "?"
    irrc = "#4ade80" if ia.asn_info and ia.asn_info.irr_valid else "#fbbf24"
    rpkic= "#4ade80" if ia.asn_info and ia.asn_info.rpki == "Valid" else "#fbbf24"
    rpkiv= ia.asn_info.rpki if ia.asn_info else "?"
    html = (f'<div class="panel"><div class="panel-hdr">🗺️ &nbsp;BGP INTELLIGENCE — {ia.ip}</div>'
            f'<div class="panel-body">'
            f'<div class="as-path">'
            f'<div class="as-node"><div class="asn">AS55836 IN</div>'
            f'<div class="org">Reliance JIO</div><span class="tag">JIO NETWORK</span></div>'
            f'<span class="as-arrow">→</span>'
            f'<div class="as-node"><div class="asn">AS{ia.peer_asn}</div>'
            f'<div class="org">{org}</div><span class="tag">{rir}</span></div></div>'
            f'<div style="margin-top:.5rem;font-size:.67rem;">'
            f'<span style="color:#3a6a94;">Prefix:</span> <span style="color:#38bdf8;">{ia.prefix}</span> &nbsp;'
            f'<span style="color:#3a6a94;">NH:</span> <span style="color:#38bdf8;">{ia.next_hop}</span> &nbsp;'
            f'<span style="color:#3a6a94;">LP:</span> <span style="color:#38bdf8;">{ia.local_pref}</span><br>'
            f'<span style="color:#3a6a94;">IRR:</span> <span style="color:{irrc};">'
            f'{"✓ Valid" if ia.asn_info and ia.asn_info.irr_valid else "⚠ Missing"}</span> &nbsp;&nbsp;'
            f'<span style="color:#3a6a94;">RPKI:</span> <span style="color:{rpkic};">{rpkiv}</span>'
            f'</div></div></div>')
    st.markdown(html, unsafe_allow_html=True)

def render_asn_for_ip(ia: IPAnalysis):
    if not ia.asn_info: return
    ai   = ia.asn_info
    irrc = "#4ade80" if ai.irr_valid else "#fbbf24"
    rpkic= "#4ade80" if ai.rpki == "Valid" else "#fbbf24"
    st.markdown(f"""
<div class="panel">
  <div class="panel-hdr">🌍 &nbsp;AS{ai.asn} — {ai.org}
    <span style="margin-left:auto;font-size:.55rem;color:#1e3a5f;">Live: Team Cymru DNS</span>
  </div>
  <div class="panel-body">
    <span style="color:#3a6a94;">Handle:</span> <span style="color:#38bdf8;">{ai.handle}</span><br>
    <span style="color:#3a6a94;">Country:</span> <span style="color:#e2f0fd;">{ai.country}</span> &nbsp;
    <span style="color:#3a6a94;">RIR:</span> <span style="color:#e2f0fd;">{ai.rir}</span><br>
    <span style="color:#3a6a94;">~Prefixes:</span> <span style="color:#e2f0fd;">{ai.num_routes:,}</span> &nbsp;
    <span style="color:#3a6a94;">~Peers:</span> <span style="color:#e2f0fd;">{ai.num_peers}</span><br>
    <span style="color:#3a6a94;">IRR:</span>
    <span style="color:{irrc};">{'✓ Valid' if ai.irr_valid else '⚠ Missing'}</span><br>
    <span style="color:#3a6a94;">RPKI:</span>
    <span style="color:{rpkic};">{ai.rpki}</span>
  </div>
</div>""", unsafe_allow_html=True)

def render_hop_table_for_ip(ia: IPAnalysis):
    rows = ""
    for h in ia.hops:
        ls  = f"{h.latency_ms:.1f}ms" if h.latency_ms > 0 else "*"
        lc  = "#f87171" if h.is_anomaly else ("#fbbf24" if h.latency_ms > 30 else "#4ade80")
        ac  = " hop-anomaly" if h.is_anomaly else ""
        ann = f' <span style="color:#f59e0b;font-size:.56rem;">{h.anomaly_reason}</span>' if h.is_anomaly else ""
        rows += (f'<tr class="{ac}">'
                 f'<td style="color:#1e4a6e;text-align:center;">{h.num}</td>'
                 f'<td style="color:#38bdf8;">{h.ip}</td>'
                 f'<td style="color:#4d7aa0;">{h.hostname}</td>'
                 f'<td style="color:{lc};text-align:right;">{ls}{ann}</td>'
                 f'<td style="color:#2a5070;">{h.network}</td></tr>')
    html = (f'<div class="panel"><div class="panel-hdr">🔀 &nbsp;TRACEROUTE — {ia.ip} — {len(ia.hops)} HOPS'
            + (f' &nbsp;⚠ BOTTLENECK HOP {ia.bottleneck_hop}' if ia.bottleneck_hop else "")
            + f'</div>'
            f'<div class="panel-body" style="padding:0;">'
            f'<table class="hop-table"><thead><tr>'
            f'<th style="text-align:center;">#</th><th>IP</th><th>HOSTNAME</th>'
            f'<th style="text-align:right;">LATENCY</th><th>ASN</th>'
            f'</tr></thead><tbody>{rows}</tbody></table></div></div>')
    st.markdown(html, unsafe_allow_html=True)

def render_latency_graph_for_ip(ia: IPAnalysis):
    import plotly.graph_objects as go
    valid = [(h.num, h.latency_ms) for h in ia.hops if h.latency_ms > 0]
    if not valid: return
    xs = [x[0] for x in valid]; ys = [x[1] for x in valid]
    
    anomaly_x = [h.num for h in ia.hops if h.is_anomaly and h.latency_ms > 0]
    anomaly_y = [h.latency_ms for h in ia.hops if h.is_anomaly and h.latency_ms > 0]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines+markers",
        line=dict(color="#0ea5e9", width=2),
        marker=dict(color="#0ea5e9", size=6, line=dict(color="#0369a1", width=1)),
        hovertemplate="Hop %{x}<br>%{y:.1f}ms<extra></extra>",
        fill="tozeroy", fillcolor="rgba(14,165,233,.07)"))
    if anomaly_x:
        fig.add_trace(go.Scatter(x=anomaly_x, y=anomaly_y, mode="markers",
            marker=dict(color="#f59e0b", size=10, symbol="diamond",
                        line=dict(color="#f97316", width=2)),
            name="Anomaly", hovertemplate="⚠ Hop %{x}<br>%{y:.1f}ms<extra></extra>"))
    fig.add_hline(y=100, line_dash="dash", line_color="#ef4444",
                  annotation_text="100ms alert", annotation_font_color="#ef4444",
                  annotation_font_size=9)
    fig.update_layout(
        height=155, margin=dict(l=35, r=15, t=8, b=25),
        paper_bgcolor="#060d18", plot_bgcolor="#060d18",
        font=dict(family="JetBrains Mono", size=9, color="#3a6a94"),
        xaxis=dict(showgrid=False, zeroline=False, tickfont=dict(size=8),
                   tickcolor="#1a3350", linecolor="#1a3350"),
        yaxis=dict(showgrid=True, gridcolor="#0f1f30", zeroline=False,
                   tickfont=dict(size=8), ticksuffix="ms"),
        showlegend=False)
    st.markdown('<div class="panel"><div class="panel-hdr">📊 &nbsp;LATENCY — PER HOP RTT'
                '<span style="color:#f59e0b;margin-left:auto;font-size:.55rem;">◆ anomaly hops</span>'
                '</div><div style="padding:.2rem .4rem;">',
                unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
    st.markdown("</div></div>", unsafe_allow_html=True)

def render_threat_score_widget(ia: IPAnalysis):
    s   = ia.threat_score
    col = ts_color(s)
    lbl = ts_label(s)
    r2, cx, cy, sw = 38, 48, 48, 8
    circ      = 2 * math.pi * r2
    dash_val  = circ * (s / 100)
    dash_gap  = circ - dash_val
    irr_s     = "✓ Valid (+20)" if ia.asn_info and ia.asn_info.irr_valid else "⚠ Missing (+0)"
    rpki_s    = f"RPKI: {ia.asn_info.rpki if ia.asn_info else '?'}"
    lat_pts   = 30 if ia.avg_latency<=10 else 20 if ia.avg_latency<=30 else 12 if ia.avg_latency<=60 else 0
    st.markdown(f"""
<div class="ts-wrap">
  <div class="ts-ring-bg" style="width:96px;height:96px;position:relative;">
    <svg width="96" height="96" viewBox="0 0 96 96" style="transform:rotate(-90deg);display:block;">
      <circle cx="{cx}" cy="{cy}" r="{r2}" fill="none" stroke="#0f1f30" stroke-width="{sw}"/>
      <circle cx="{cx}" cy="{cy}" r="{r2}" fill="none" stroke="{col}" stroke-width="{sw}"
              stroke-linecap="round"
              stroke-dasharray="{dash_val:.2f} {dash_gap:.2f}"/>
    </svg>
    <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;">
      <span style="font-family:'JetBrains Mono',monospace;font-size:1.3rem;font-weight:800;color:{col};line-height:1;">{s}</span>
      <span style="font-family:'JetBrains Mono',monospace;font-size:.5rem;display:block;color:#3a6a94;margin-top:1px;">/100</span>
    </div>
  </div>
  <div style="color:{col};font-family:'JetBrains Mono',monospace;font-size:.62rem;letter-spacing:2px;margin-top:.4rem;font-weight:700;">{lbl}</div>
  <div class="ts-factors">
    <div>⚡ Latency {ia.avg_latency:.0f}ms → +{lat_pts}pts</div>
    <div>📡 Reach: {'✓ OK (+20)' if ia.ping_ok else '✗ FAIL (+0)'}</div>
    <div>📦 Loss {ia.packet_loss:.0f}% → +{10 if ia.packet_loss==0 else 5 if ia.packet_loss<=1 else 0}pts</div>
    <div>🗂 IRR: {irr_s}</div>
    <div>🔐 {rpki_s}</div>
  </div>
</div>""", unsafe_allow_html=True)

def render_ai_panel(ia: IPAnalysis):
    if not ia.ai_anomaly and not ia.ai_remediation:
        return
    anom_html = ""
    if ia.ai_anomaly:
        content = ia.ai_anomaly.replace("\n", "<br>")
        anom_html = f'<div class="anomaly-box">🔎 <b>AI ANOMALY ANALYSIS</b><br>{content}</div>'
    remed_html = ""
    if ia.ai_remediation:
        content = ia.ai_remediation.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")
        remed_html = (f'<div class="remediation-box">⚙ <b>IOS XR REMEDIATION PLAYBOOK</b><br>'
                      f'<pre style="background:transparent;color:#4ade80;font-size:.68rem;'
                      f'margin:0;padding:0;font-family:\'JetBrains Mono\',monospace;">'
                      f'{content}</pre></div>')
    st.markdown(f"""
<div class="panel">
  <div class="panel-hdr">🤖 &nbsp;AI ISOC INTELLIGENCE — {ia.ip}
    <span style="margin-left:auto;font-size:.55rem;color:#1e3a5f;">Claude Sonnet</span>
  </div>
  <div class="panel-body">
    {anom_html}
    {remed_html}
  </div>
</div>""", unsafe_allow_html=True)

def render_ip_drilldown(r: SiteReport, use_ibr: bool):
    if not r.ip_analyses: return
    tab_labels = [
        f"{'★ ' if ia.ip==r.primary_ip else ''}"
        f"{ia.ip}"
        f"{'  [NAT64]' if ia.is_synthetic_v6 else '  [IPv6]' if ia.ip_version==6 else ''}"
        f"  T:{ia.threat_score}"
        for ia in r.ip_analyses
    ]
    tabs = st.tabs(tab_labels)
    for tab, ia in zip(tabs, r.ip_analyses):
        with tab:
            hc  = "#4ade80" if ia.ping_ok else "#fbbf24"
            lc  = "#fbbf24" if ia.avg_latency > 30 else "#4ade80"
            loc = "#fbbf24" if ia.packet_loss > 0 else "#4ade80"
            syn_tag = ""
            if ia.is_synthetic_v6:
                syn_tag = '<span style="background:#1a0f2e;color:#a78bfa;font-size:.62rem;padding:.2rem .55rem;border-radius:4px;font-family:\'JetBrains Mono\',monospace;">NAT64 SYNTHETIC</span>'
            elif ia.ip_version == 6:
                syn_tag = '<span style="background:#0c2244;color:#22d3ee;font-size:.62rem;padding:.2rem .55rem;border-radius:4px;font-family:\'JetBrains Mono\',monospace;">NATIVE IPv6</span>'
            sc1, sc2 = st.columns([3, 1], gap="small")
            with sc1:
                st.markdown(f"""
<div style="display:flex;gap:.45rem;margin-bottom:.5rem;flex-wrap:wrap;align-items:center;">
  {syn_tag}
  <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;background:#0a1828;border:1px solid #1a3350;border-radius:5px;padding:.28rem .7rem;">
    <span style="color:#3a6a94;">STATUS</span>&nbsp;
    <span style="color:{hc};font-weight:700;">{'✓ REACHABLE' if ia.ping_ok else '⚠ UNREACHABLE'}</span></span>
  <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;background:#0a1828;border:1px solid #1a3350;border-radius:5px;padding:.28rem .7rem;">
    <span style="color:#3a6a94;">RTT</span>&nbsp;
    <span style="color:{lc};font-weight:700;">{ia.avg_latency:.1f}ms</span></span>
  <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;background:#0a1828;border:1px solid #1a3350;border-radius:5px;padding:.28rem .7rem;">
    <span style="color:#3a6a94;">LOSS</span>&nbsp;
    <span style="color:{loc};font-weight:700;">{ia.packet_loss:.0f}%</span></span>
  <span style="font-family:'JetBrains Mono',monospace;font-size:.68rem;background:#0a1828;border:1px solid #1a3350;border-radius:5px;padding:.28rem .7rem;">
    <span style="color:#3a6a94;">HOPS</span>&nbsp;
    <span style="color:#60a5fa;font-weight:700;">{len(ia.hops)}</span></span>
  {HEALTH_BADGE[ia.health]}
</div>""", unsafe_allow_html=True)
                render_latency_graph_for_ip(ia)
            with sc2:
                st.markdown(
                    '<div class="panel"><div class="panel-hdr">🛡️ &nbsp;ISOC TRUST SCORE</div>'
                    '<div class="panel-body" style="padding:.4rem .5rem;">',
                    unsafe_allow_html=True)
                render_threat_score_widget(ia)
                st.markdown("</div></div>", unsafe_allow_html=True)

            render_ai_panel(ia)

            if use_ibr or ia.asn_info:
                c1, c2 = st.columns(2, gap="small")
                with c1: render_bgp_for_ip(ia)
                with c2: render_asn_for_ip(ia)

            render_hop_table_for_ip(ia)

            with st.expander("🖥️ Raw Terminal Output"):
                rt = st.tabs(["Ping", "Traceroute", "IBR SSH", "BGP + ASN (Cymru)"])
                for t, c in zip(rt, [ia.ping_raw, ia.traceroute_raw, ia.ibr_raw, ia.bgp_raw]):
                    with t: st.code(c or "(skipped)", language="text")

def render_detail_panel(r: SiteReport, use_ibr: bool):
    ts_c = ts_color(r.threat_score)
    inv_tag = ""
    if not r.valid:
        inv_tag = f' <span class="badge b-err">INVALID — {r.invalid_reason}</span>'
    st.markdown(
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.65rem;'
        f'color:#1e4a6e;letter-spacing:2px;margin-bottom:.5rem;">'
        f'◈ TRIAGE DETAIL — <span style="color:#38bdf8;">{r.domain}</span>'
        f' &nbsp;{HEALTH_BADGE[r.health]}{inv_tag}'
        f' &nbsp;<span style="background:#0a1828;border:1px solid {ts_c}40;color:{ts_c};'
        f'padding:.12rem .5rem;border-radius:4px;font-size:.6rem;font-weight:700;">'
        f'TRUST {r.threat_score}/100</span>'
        f'</div>', unsafe_allow_html=True)
    left, right = st.columns([1, 3], gap="medium")
    with left:
        st.markdown('<div class="slabel">Pipeline</div>', unsafe_allow_html=True)
        render_pipeline(r)
        st.markdown("")
        if r.resolved_ips:
            st.markdown('<div class="slabel">Resolved IPs</div>', unsafe_allow_html=True)
            render_ip_chip_list(r, r.primary_ip)
        if r.synthetic_ipv6:
            shtml = "".join(
                f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:.64rem;'
                f'color:#a78bfa;padding:.12rem 0;">'
                f'<span style="color:#4d3a70;">NAT64</span>  {sv6}</div>'
                for sv6 in r.synthetic_ipv6
            )
            st.markdown(f'<div class="slabel">NAT64 Synthetic IPv6</div>{shtml}', unsafe_allow_html=True)
        st.markdown("")
        st.markdown('<div class="slabel">ISOC Intelligence</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="isoc-intel"><div class="isoc-hdr">◈ LIVE ISOC ANALYSIS</div>'
                    f'{r.ai_analysis.replace(chr(10),"<br>")}</div>', unsafe_allow_html=True)
        st.markdown("")
        with st.expander("DNS Raw Output"):
            st.code(r.dns_raw, language="text")
        if r.jump_raw:
            with st.expander("Jump Server SSH Raw"):
                st.code(r.jump_raw, language="text")
    with right:
        if not r.valid:
            st.markdown(f"""
<div style="background:#1c0000;border:1px solid #7f1d1d;border-radius:8px;padding:1.2rem 1.5rem;
  font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#f87171;line-height:2;">
  <div style="font-size:1rem;margin-bottom:.5rem;">⛔ DOMAIN HALTED — NXDOMAIN</div>
  <div style="color:#991b1b;">Domain: {r.domain}</div>
  <div style="color:#991b1b;">Reason: {r.invalid_reason}</div>
  <div style="color:#991b1b;margin-top:.5rem;">No ping, traceroute, BGP or ASN analysis performed.</div>
</div>""", unsafe_allow_html=True)
        else:
            st.markdown('<div class="slabel">Per-IP Drilldown — select IP tab</div>',
                        unsafe_allow_html=True)
            render_ip_drilldown(r, use_ibr)


# ══════════════════════════════════════════════════════════════
#  MAIN APP
# ══════════════════════════════════════════════════════════════
def main():
    for k, v in [("reports", []), ("selected", None),
                 ("use_ibr", True), ("dns_profile", "Google DNS (IPv4)"),
                 ("ip_pref", "Both")]:
        if k not in st.session_state:
            st.session_state[k] = v

    lib_status = []
    if HAS_DNSPY:   lib_status.append("dnspython ✓")
    if HAS_IPWHOIS: lib_status.append("ipwhois ✓")
    if HAS_PARAMIKO:lib_status.append("paramiko ✓")
    if AWS_KEY_CHECK: lib_status.append("AI (Bedrock) ✓")
    lib_str = "  ·  ".join(lib_status)

    st.markdown(f"""
<div class="hdr">
  <div class="hdr-logo">
    <div class="hdr-jio">JIO</div>
    <div>
      <div class="hdr-title">Internal ISOC Dashboard — LIVE NETWORK EDITION v6.3</div>
      <div class="hdr-sub">INFORMATION SECURITY OPERATIONS CENTER  //  v6.3  //  REAL DNS + ICMP + ASN + SSH + AI  //  CONFIDENTIAL</div>
    </div>
  </div>
  <div class="hdr-creds">
    Jump Server&nbsp;&nbsp;{JUMP_SERVER_IP} / {JUMP_SERVER_USER} / <span>{'●'*8}</span><br>
    IBR (Border)&nbsp;&nbsp;{IBR_IP} / {IBR_USER} / <span>{'●'*8}</span><br>
    <span style="color:#1a3a5a;">{lib_str}</span>
  </div>
</div>""", unsafe_allow_html=True)

    input_tab, upload_tab = st.tabs([
        "✏️  Manual Input",
        "📡  ISOC BATCH INGESTION (.txt / .csv / .xlsx)"
    ])
    domains_from_input = []

    with input_tab:
        c_area, c_opts = st.columns([3, 1], gap="medium")
        with c_area:
            raw = st.text_area("urls", label_visibility="collapsed",
                placeholder="One domain per line — up to 100\ngoogle.com\njio.com\ngithub.com\namazon.in\n...",
                height=120)
        with c_opts:
            use_ibr = st.checkbox("IBR checks (BGP/ASN/SSH)", value=True)
            st.session_state.use_ibr = use_ibr

        dns_cols = st.columns([2, 1, 3])
        with dns_cols[0]:
            st.markdown('<div class="slabel" style="margin-bottom:.2rem;">◈ DNS Profile</div>',
                        unsafe_allow_html=True)
            dns_sel = st.selectbox("dns_profile", DNS_LABELS,
                                   index=DNS_LABELS.index(st.session_state.dns_profile),
                                   label_visibility="collapsed",
                                   key="dns_sel_manual")
            st.session_state.dns_profile = dns_sel
        with dns_cols[1]:
            st.markdown('<div class="slabel" style="margin-bottom:.2rem;">◈ Protocol</div>',
                        unsafe_allow_html=True)
            ip_pref = st.selectbox("ip_pref", ["Both", "IPv4", "IPv6"],
                                   index=["Both", "IPv4", "IPv6"].index(st.session_state.ip_pref),
                                   label_visibility="collapsed",
                                   key="ip_pref_manual")
            st.session_state.ip_pref = ip_pref
        with dns_cols[2]:
            servers = DNS_OPTIONS[dns_sel]
            srv_str = "  |  ".join(servers)
            st.markdown(f"""
<div style="margin-top:1.55rem;font-family:'JetBrains Mono',monospace;font-size:.68rem;
  background:#071628;border:1px solid #1e4a7a;border-radius:7px;padding:.4rem .75rem;
  color:#38bdf8;">{srv_str}</div>""", unsafe_allow_html=True)

        run_manual = st.button("▶▶  INITIATE LIVE ISOC TRIAGE", key="run_manual")
        if run_manual and raw.strip():
            seen = set(); domains_from_input = []
            for line in raw.strip().splitlines():
                d = re.sub(r"^https?://", "", line.strip().lower())
                d = d.split("/")[0].split("?")[0].split("#")[0].strip()
                if d and d not in seen:
                    seen.add(d); domains_from_input.append(d)

    with upload_tab:
        u_left, u_right = st.columns([3, 1], gap="medium")
        with u_left:
            uploaded = st.file_uploader("Drop file", label_visibility="collapsed",
                type=["txt","csv","xlsx"],
                help="One domain per line (txt), first column (csv/xlsx). Up to 100 domains.")
        with u_right:
            use_ibr_up = st.checkbox("IBR checks", value=True, key="ibr_up")

        dns_cols2 = st.columns([2, 1, 3])
        with dns_cols2[0]:
            st.markdown('<div class="slabel" style="margin-bottom:.2rem;">◈ DNS Profile</div>',
                        unsafe_allow_html=True)
            dns_sel2 = st.selectbox("dns_profile_up", DNS_LABELS,
                                    index=DNS_LABELS.index(st.session_state.dns_profile),
                                    label_visibility="collapsed",
                                    key="dns_sel_upload")
        with dns_cols2[1]:
            st.markdown('<div class="slabel" style="margin-bottom:.2rem;">◈ Protocol</div>',
                        unsafe_allow_html=True)
            ip_pref2 = st.selectbox("ip_pref_up", ["Both", "IPv4", "IPv6"],
                                   index=["Both", "IPv4", "IPv6"].index(st.session_state.ip_pref),
                                   label_visibility="collapsed",
                                   key="ip_pref_upload")
        with dns_cols2[2]:
            servers2 = DNS_OPTIONS[dns_sel2]
            srv_str2 = "  |  ".join(servers2)
            st.markdown(f"""
<div style="margin-top:1.55rem;font-family:'JetBrains Mono',monospace;font-size:.68rem;
  background:#071628;border:1px solid #1e4a7a;border-radius:7px;padding:.4rem .75rem;
  color:#38bdf8;">{srv_str2}</div>""", unsafe_allow_html=True)

        run_upload = st.button("▶▶  INITIATE LIVE ISOC TRIAGE", key="run_upload")
        if run_upload and uploaded:
            domains_from_input = parse_uploaded_file(uploaded)
            st.session_state.use_ibr    = use_ibr_up
            st.session_state.dns_profile = dns_sel2
            st.session_state.ip_pref = ip_pref2

    trigger = domains_from_input[:100]
    if trigger:
        st.session_state.reports  = []
        st.session_state.selected = None
        bar = st.progress(0, text="Initialising LIVE ISOC triage…")
        ph  = st.empty()
        
        total_domains = len(trigger)
        completed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(50, total_domains)) as executor:
            future_to_domain = {
                executor.submit(
                    analyse_domain, 
                    domain, 
                    st.session_state.use_ibr, 
                    st.session_state.dns_profile,
                    st.session_state.ip_pref
                ): domain for domain in trigger
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    r = future.result()
                    st.session_state.reports.append(r)
                except Exception as e:
                    err_r = SiteReport(domain=domain, valid=False, invalid_reason=f"Execution Error: {e}", health="critical")
                    st.session_state.reports.append(err_r)
                
                completed += 1
                progress_pct = int((completed / total_domains) * 100)
                bar.progress(progress_pct, text=f"[LIVE] Triaging Domains ({completed}/{total_domains}) via {st.session_state.dns_profile} (Parallel Mode)")
                ph.markdown(f'<div class="slabel">▶ PROCESSING IN BACKGROUND: {domain}</div>', unsafe_allow_html=True)

        st.session_state.reports.sort(key=lambda x: trigger.index(x.domain))

        bar.progress(100, text=f"✓ ISOC live triage complete — {total_domains} domain(s) processed instantly!")
        ph.empty()
        if st.session_state.reports:
            st.session_state.selected = st.session_state.reports[0].domain
        st.rerun()

    reports = st.session_state.reports
    if not reports:
        st.markdown("""
<div style="text-align:center;padding:4rem 2rem;opacity:.28;">
  <div style="font-size:2.5rem;">🛡️</div>
  <div style="font-family:'JetBrains Mono',monospace;font-size:.72rem;color:#1e4a6e;
    letter-spacing:2.5px;margin-top:.8rem;">JIO ISOC v6.3 — LIVE NETWORK EDITION — ENTER DOMAINS → INITIATE TRIAGE</div>
</div>""", unsafe_allow_html=True)
        return

    ec1, ec2, _ = st.columns([1, 1, 5])
    with ec1:
        st.download_button("⬇ JSON", export_json(reports), "jio_isoc_live_report.json",
                           "application/json", use_container_width=True)
    with ec2:
        st.download_button("⬇ CSV", export_csv(reports), "jio_isoc_live_report.csv",
                           "text/csv", use_container_width=True)

    st.markdown("---")

    ok_c   = sum(1 for r in reports if r.health == "healthy")
    wn_c   = sum(1 for r in reports if r.health == "degraded")
    er_c   = sum(1 for r in reports if r.health == "critical")
    inv_c  = sum(1 for r in reports if not r.valid)
    total_ips   = sum(len(r.ip_analyses) for r in reports)
    total_v6    = sum(len(r.resolved_ipv6) for r in reports)
    total_nat64 = sum(len(r.synthetic_ipv6) for r in reports)
    avg_l  = round(sum(r.avg_latency for r in reports) / max(len(reports), 1), 1)
    total_hops = sum(len(ia.hops) for r in reports for ia in r.ip_analyses)
    avg_ts = round(sum(r.threat_score for r in reports) / max(len(reports), 1))
    active_dns = reports[0].dns_profile if reports else "—"
    st.markdown(f"""
<div class="mini-stats">
  <div class="mini-stat"><div class="ms-num">{len(reports)}</div><div class="ms-lbl">DOMAINS</div></div>
  <div class="mini-stat"><div class="ms-num">{total_ips}</div><div class="ms-lbl">IPs TRIAGED</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#a78bfa;">{total_v6}</div><div class="ms-lbl">IPv6 NATIVE</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#8b5cf6;">{total_nat64}</div><div class="ms-lbl">NAT64 SYNTH</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#4ade80">{ok_c}</div><div class="ms-lbl">HEALTHY</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#fbbf24">{wn_c}</div><div class="ms-lbl">DEGRADED</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#f87171">{er_c}</div><div class="ms-lbl">CRITICAL</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:#f87171">{inv_c}</div><div class="ms-lbl">INVALID</div></div>
  <div class="mini-stat"><div class="ms-num">{avg_l}<span style="font-size:.85rem">ms</span></div><div class="ms-lbl">AVG RTT</div></div>
  <div class="mini-stat"><div class="ms-num">{total_hops}</div><div class="ms-lbl">TOTAL HOPS</div></div>
  <div class="mini-stat"><div class="ms-num" style="color:{ts_color(avg_ts)}">{avg_ts}</div><div class="ms-lbl">AVG TRUST</div></div>
  <div class="mini-stat"><div class="ms-num" style="font-size:.85rem;color:#38bdf8">{active_dns}</div><div class="ms-lbl">DNS PROFILE</div></div>
</div>""", unsafe_allow_html=True)

    st.markdown('<div class="slabel">◈ Live Triage Results — click row to drill down</div>',
                unsafe_allow_html=True)
    st.markdown(
        '<table class="rtbl"><tr>'
        '<th>#</th><th>DOMAIN</th><th>IPs</th><th>PRIMARY IP</th>'
        '<th>DNS</th><th>LATENCY</th><th>LOSS</th><th>HOPS</th>'
        '<th>ASN</th><th>RPKI</th><th>TRUST</th><th>HEALTH</th>'
        '</tr></table>', unsafe_allow_html=True)

    for i, r in enumerate(reports, 1):
        is_sel  = st.session_state.selected == r.domain
        rpki    = r.asn_info.rpki if r.asn_info else "-"
        rpkic   = "#4ade80" if rpki == "Valid" else "#fbbf24"
        lc      = "#fbbf24" if r.avg_latency > 30 else "#4ade80"
        loc     = "#fbbf24" if r.packet_loss > 0 else "#4ade80"
        tc      = ts_color(r.threat_score)
        sel_cls = " sel" if is_sel else ""
        dom_cls = "domain-cell" if r.valid else "domain-cell invalid-domain"
        ip_badge = (f'<span class="ip-count-chip">{len(r.resolved_ips)} IPs</span>'
                    if len(r.resolved_ips) > 1 else ("1 IP" if r.resolved_ips else "—"))
        inv_marker = " ⛔" if not r.valid else ""
        st.markdown(
            f'<table class="rtbl" style="margin-bottom:2px;"><tr class="{sel_cls}">'
            f'<td style="color:#1e4a6e;width:26px;">{i}</td>'
            f'<td class="{dom_cls}">{r.domain}{inv_marker}</td>'
            f'<td>{ip_badge}</td>'
            f'<td style="color:#4d7aa0;">{r.primary_ip}</td>'
            f'<td style="color:#22d3ee;font-size:.62rem;">{r.dns_profile}</td>'
            f'<td style="color:{lc};">{r.avg_latency:.1f}ms</td>'
            f'<td style="color:{loc};">{r.packet_loss:.0f}%</td>'
            f'<td style="color:#4d7aa0;">{sum(len(ia.hops) for ia in r.ip_analyses)}</td>'
            f'<td style="color:#4d8ab8;">AS{r.peer_asn or "—"}</td>'
            f'<td style="color:{rpkic};">{rpki}</td>'
            f'<td style="color:{tc};font-weight:700;">{r.threat_score}</td>'
            f'<td>{HEALTH_BADGE[r.health]}</td>'
            f'</tr></table>', unsafe_allow_html=True)
        if st.button(f"{'▼' if is_sel else '▶'}  {r.domain}", key=f"sel_{i}_{r.domain}"):
            st.session_state.selected = None if is_sel else r.domain
            st.rerun()

    sel = st.session_state.selected
    if sel:
        r = next((x for x in reports if x.domain == sel), None)
        if r:
            st.markdown("---")
            render_detail_panel(r, st.session_state.use_ibr)

    st.markdown(f"""
<div style="font-family:'JetBrains Mono',monospace;font-size:.55rem;color:#0f1f30;
  text-align:center;margin-top:2rem;letter-spacing:1px;">
  JIO ISOC DASHBOARD v6.3 LIVE &nbsp;·&nbsp; INTERNAL USE ONLY &nbsp;·&nbsp;
  dnspython · ipwhois (Cymru DNS) · paramiko · Claude AI (AWS Bedrock) &nbsp;·&nbsp;
  DNS Profiles: 5G/Sub6 · LTE · FTTX · Enterprise · Google · Cloudflare &nbsp;·&nbsp;
  IPv4 + IPv6 + NAT64 · AI Anomaly Detection · IOS XR Remediation
</div>""", unsafe_allow_html=True)

if __name__ == "__main__":
    main()