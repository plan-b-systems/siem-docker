// DNS query log parser — recognizes BIND, Unbound, and dnsmasq query/response
// log formats and normalises into the common envelope used by the rule engine.
//
// MDRv2 Stage 2 (T11). Customer's DNS resolver (BIND/Unbound/dnsmasq) ships
// syslog to our receiver; this parser extracts the query name, type, and
// client IP so detection rules (DNS tunneling, NRD, malicious-domain match)
// can match against indexed fields rather than free-text.
//
// Normalised fields produced:
//   dns_qname           — queried domain name (e.g. "example.com")
//   dns_qtype           — query type (A, AAAA, TXT, CNAME, MX, ...)
//   dns_client_ip       — IP of the resolver client that asked
//   dns_response_code   — present for response logs (NOERROR, NXDOMAIN, SERVFAIL)
//   dns_query_size_bytes — total query size when known (used by DNS-tunneling rules)
//   src_ip              — alias for dns_client_ip so existing rules using src_ip work

'use strict'

// BIND query log line example:
//   "26-Apr-2026 14:32:01.123 client @0xCAFEBABE 192.168.1.10#54321 (example.com): query: example.com IN A +ED (10.0.0.1)"
const BIND_RE = /client\s+(?:@0x[0-9a-fA-F]+\s+)?(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)#\d+\s+\([^)]*\):\s*query:\s+(\S+)\s+(?:IN|CH|HS)\s+(\S+)/

// Unbound query log:
//   "[1714138321] unbound[12345:0] info: 10.0.0.5 example.com. A IN"
const UNBOUND_RE = /unbound\[[^\]]+\]\s+info:\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+(\S+?)\.?\s+(\S+)\s+(?:IN|CH|HS)/

// dnsmasq:
//   "Apr 26 14:32:01 router dnsmasq[1234]: query[A] example.com from 10.0.0.5"
//   "Apr 26 14:32:01 router dnsmasq[1234]: reply example.com is 1.2.3.4"
const DNSMASQ_QUERY_RE = /dnsmasq\[\d+\]:\s+query\[(\S+)\]\s+(\S+)\s+from\s+(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)/
const DNSMASQ_REPLY_RE = /dnsmasq\[\d+\]:\s+reply\s+(\S+)\s+is\s+(\S+)/

// PowerDNS recursor query log:
//   "msg='Question' subject='example.com|A' qname='example.com'"
const POWERDNS_RE = /qname='([^']+)'.*?qtype='([^']+)'.*?(?:src='|remote=')(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)/

function detect(msg) {
  return (
    BIND_RE.test(msg) ||
    UNBOUND_RE.test(msg) ||
    DNSMASQ_QUERY_RE.test(msg) ||
    DNSMASQ_REPLY_RE.test(msg) ||
    POWERDNS_RE.test(msg)
  )
}

function parse(msg) {
  let m = BIND_RE.exec(msg)
  if (m) {
    return {
      dns_client_ip: m[1],
      src_ip: m[1],
      dns_qname: stripTrailingDot(m[2]),
      dns_qtype: m[3].toUpperCase(),
      dns_query_size_bytes: msg.length,
      event_category: 'network',
      event_action: 'dns_query',
    }
  }
  m = UNBOUND_RE.exec(msg)
  if (m) {
    return {
      dns_client_ip: m[1],
      src_ip: m[1],
      dns_qname: stripTrailingDot(m[2]),
      dns_qtype: m[3].toUpperCase(),
      dns_query_size_bytes: msg.length,
      event_category: 'network',
      event_action: 'dns_query',
    }
  }
  m = DNSMASQ_QUERY_RE.exec(msg)
  if (m) {
    return {
      dns_qtype: m[1].toUpperCase(),
      dns_qname: stripTrailingDot(m[2]),
      dns_client_ip: m[3],
      src_ip: m[3],
      dns_query_size_bytes: msg.length,
      event_category: 'network',
      event_action: 'dns_query',
    }
  }
  m = DNSMASQ_REPLY_RE.exec(msg)
  if (m) {
    return {
      dns_qname: stripTrailingDot(m[1]),
      dns_response_value: m[2],
      dns_response_code: 'NOERROR',
      event_category: 'network',
      event_action: 'dns_reply',
    }
  }
  m = POWERDNS_RE.exec(msg)
  if (m) {
    return {
      dns_qname: stripTrailingDot(m[1]),
      dns_qtype: m[2].toUpperCase(),
      dns_client_ip: m[3],
      src_ip: m[3],
      dns_query_size_bytes: msg.length,
      event_category: 'network',
      event_action: 'dns_query',
    }
  }
  return null
}

function stripTrailingDot(name) {
  return name.endsWith('.') ? name.slice(0, -1) : name
}

module.exports = { detect, parse }
