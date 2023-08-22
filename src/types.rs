use std::fmt;

use crate::{ip::IpFamily, Ip, Ipv4, Ipv6, L4Proto, Mac, MetricsDir, MetricsReason, Port};
use bitflags::bitflags;
use plain::Plain;
use tuitable_derive::TuiTable;

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct PolicyKey {
    len: u32,
    sec_label: u32,
    egress: bool,
    protocol: L4Proto,
    dport: Port,
}

unsafe impl Plain for PolicyKey {}

bitflags! {
    #[derive(Default)]
    pub struct PolicyEntryFlags : u8 {
        const DENY = 1;
        const WILDCARD_PROTOCOL = 1 << 1;
        const WILDCARD_DPORT = 1 << 2;
    }
}

impl fmt::Display for PolicyEntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct PolicyEntry {
    proxy_port: Port,
    flags: PolicyEntryFlags,
    auth_type: u8,
    pad1: u16,
    pad2: u16,
    packets: u64,
    bytes: u64,
}

unsafe impl Plain for PolicyEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EndpointKey {
    addr: Ip,
    family: IpFamily,
    key: u8,
    cluster_id: u8,
}

unsafe impl Plain for EndpointKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct TunnelKey {
    addr: Ip,
    family: IpFamily,
    cluster_id: u8,
}

unsafe impl Plain for TunnelKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct TunnelValue {
    addr: Ip,
    family: IpFamily,
    key: u8,
    node_id: u16,
}

unsafe impl Plain for TunnelValue {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EndpointInfo {
    ifindex: u32,
    pad: u16,
    lxc_id: u16,
    flags: u32,
    pad2: u32,
    mac: Mac,
    pad3: u16,
    node_mac: Mac,
    pad4: u16,
    sec_id: u32,
}

unsafe impl Plain for EndpointInfo {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EdtId {
    id: u64,
}

unsafe impl Plain for EdtId {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EdtInfo {
    bps: u64,
    t_last: u64,
    t_horizon_drop: u64,
}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct RemoteEndpointInfo {
    sec_identity: u32,
    tunnel_endpoint: Ipv4,
    node_id: u16,
    key: u8,
}

unsafe impl Plain for RemoteEndpointInfo {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct AuthKey {
    local_sec_label: u32,
    remote_sec_label: u32,
    remote_node_id: u16,
    auth_type: u8,
}

unsafe impl Plain for AuthKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct AuthInfo {
    expiration: u64,
}

unsafe impl Plain for AuthInfo {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct MetricsKey {
    reason: MetricsReason,
    dir: MetricsDir,
}

unsafe impl Plain for MetricsKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct MetricsValue {
    count: u64,
    bytes: u64,
}

unsafe impl Plain for MetricsValue {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EgressGwPolicyKey {
    saddr: Ipv4,
    daddr: Ipv4,
}

unsafe impl Plain for EgressGwPolicyKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EgressGwPolicyEntry {
    egress_ip: Ipv4,
    gateway_ip: Ipv4,
}

unsafe impl Plain for EgressGwPolicyEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6VrfKey4 {
    src_ip: Ipv4,
    dst_cidr: Ipv4,
}

unsafe impl Plain for Srv6VrfKey4 {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6VrfKey6 {
    src_ip: Ipv6,
    dst_cidr: Ipv6,
}

unsafe impl Plain for Srv6VrfKey6 {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6PolicyKey4 {
    vrf_id: u32,
    dst_cidr: Ipv4,
}

unsafe impl Plain for Srv6PolicyKey4 {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6PolicyKey6 {
    vrf_id: u32,
    dst_cidr: Ipv6,
}

unsafe impl Plain for Srv6PolicyKey6 {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6Ipv4_2tuple {
    src: Ipv4,
    dst: Ipv4,
}

unsafe impl Plain for Srv6Ipv4_2tuple {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Srv6Ipv6_2tuple {
    src: Ipv6,
    dst: Ipv6,
}

unsafe impl Plain for Srv6Ipv6_2tuple {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct VtepKey {
    vtep_ip: Ipv4,
}

unsafe impl Plain for VtepKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct VtepValue {
    vtep_mac: u64,
    tunnel_endpoint: u32,
}

unsafe impl Plain for VtepValue {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct EncryptConfig {
    encrypt_key: u8,
}

unsafe impl Plain for EncryptConfig {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv6CtTuple {
    // saddr 和 daddr 是反的
    daddr: Ipv6,
    saddr: Ipv6,
    dport: Port,
    sport: Port,
    nexthdr: L4Proto,
    flags: u8,
}

unsafe impl Plain for Ipv6CtTuple {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv4CtTuple {
    // saddr 和 daddr 是反的
    daddr: Ipv4,
    saddr: Ipv4,
    dport: Port,
    sport: Port,
    nexthdr: L4Proto,
    flags: u8,
}

unsafe impl Plain for Ipv4CtTuple {}

bitflags! {
    #[derive(Default)]
    pub struct CtEntryFlags: u16 {
        const RX_CLOSING = 1;
        const TX_CLOSING = 1 << 1;
        const NAT46 = 1 << 2;
        const LB_LOOPBACK = 1 << 3;
        const SEEN_NON_SYN = 1 << 4;
        const NODE_PORT = 1 << 5;
        const PROXY_REDIRECT = 1 << 6;
        const DSR = 1 << 7;
        const FROM_L7LB = 1 << 8;
        const FROM_TUNNEL = 1 << 10;
    }
}

impl fmt::Display for CtEntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

bitflags! {
    #[derive(Default)]
    pub struct TCPFlags: u8 {
        const FIN = 1;
        const SYN = 1 << 1;
        const RST = 1 << 2;
        const PSH = 1 << 3;
        const ACK = 1 << 4;
        const URG = 1 << 5;
    }
}

impl fmt::Display for TCPFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct CtEntry {
    rx_packets: u64,
    rx_bytes: u64,
    tx_packets: u64,
    tx_bytes: u64,
    lifetime: u32,
    flags: CtEntryFlags,
    rev_nat_index: u16,
    ifindex: u16,
    tx_flags_seen: TCPFlags,
    rx_flags_seen: TCPFlags,
    src_sec_id: u32,
    last_tx_report: u32,
    last_rx_report: u32,
}

unsafe impl Plain for CtEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb6Key {
    address: Ipv6,
    dport: Port,
    backend_slot: u16,
    proto: L4Proto,
    scope: u8,
}

unsafe impl Plain for Lb6Key {}

bitflags! {
    #[derive(Default)]
    pub struct ServiceFlags: u8 {
        const SVC_FLAG_EXTERNAL_IP  = (1 << 0);  /* External IPs */
        const SVC_FLAG_NODEPORT     = (1 << 1);  /* NodePort service */
        const SVC_FLAG_EXT_LOCAL_SCOPE = (1 << 2); /* externalTrafficPolicy=Local */
        const SVC_FLAG_HOSTPORT     = (1 << 3);  /* hostPort forwarding */
        const SVC_FLAG_AFFINITY     = (1 << 4);  /* sessionAffinity=clientIP */
        const SVC_FLAG_LOADBALANCER = (1 << 5);  /* LoadBalancer service */
        const SVC_FLAG_ROUTABLE     = (1 << 6);  /* Not a surrogate/ClusterIP entry */
        const SVC_FLAG_SOURCE_RANGE = (1 << 7);  /* Check LoadBalancer source range */
    }

    #[derive(Default)]
    pub struct ServiceFlags2: u8 {
        const SVC_FLAG_LOCALREDIRECT  = (1 << 0);  /* local redirect */
        const SVC_FLAG_NAT_46X64      = (1 << 1);  /* NAT-46/64 entry */
        const SVC_FLAG_L7LOADBALANCER = (1 << 2);  /* tproxy redirect to local l7 loadbalancer */
        const SVC_FLAG_LOOPBACK       = (1 << 3);  /* hostport with a loopback hostIP */
        const SVC_FLAG_INT_LOCAL_SCOPE = (1 << 4); /* internalTrafficPolicy=Local */
        const SVC_FLAG_TWO_SCOPES     = (1 << 5);  /* two sets of backends are used for external/internal connections */
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb6Service {
    backend_id: u32,
    count: u16,
    rev_nat_index: u16,
    flags: ServiceFlags,
    flags2: ServiceFlags2,
}

unsafe impl Plain for Lb6Service {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb6Backend {
    address: Ipv6,
    port: Port,
    proto: L4Proto,
    flags: u8,
    cluster_id: u8,
}

unsafe impl Plain for Lb6Backend {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb6ReverseNat {
    address: Ipv6,
    port: Port,
}

unsafe impl Plain for Lb6ReverseNat {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv6RevnatTuple {
    cookie: u64,
    address: Ipv6,
    port: Port,
}

unsafe impl Plain for Ipv6RevnatTuple {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv6RevnatEntry {
    address: Ipv6,
    port: Port,
    rev_nat_index: u16,
}

unsafe impl Plain for Ipv6RevnatEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4Key {
    address: Ipv4,
    dport: Port,
    backend_slot: u16,
    proto: L4Proto,
    scope: u8,
}

unsafe impl Plain for Lb4Key {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4Service {
    backend_id: u32,
    count: u16,
    rev_nat_index: u16,
    flags: ServiceFlags,
    flags2: ServiceFlags2,
}

unsafe impl Plain for Lb4Service {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4BackendKey {
    backend_id: u32,
}

unsafe impl Plain for Lb4BackendKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4Backend {
    address: Ipv4,
    port: Port,
    proto: L4Proto,
    flags: u8,
    cluster_id: u8,
}

unsafe impl Plain for Lb4Backend {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4ReverseNatKey {
    rev_nat_index: u16,
}

unsafe impl Plain for Lb4ReverseNatKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4ReverseNat {
    address: Ipv4,
    port: Port,
}

unsafe impl Plain for Lb4ReverseNat {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv4RevnatTuple {
    cookie: u64,
    address: Ipv4,
    port: Port,
}

unsafe impl Plain for Ipv4RevnatTuple {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv4RevnatEntry {
    address: Ipv4,
    port: Port,
    rev_nat_index: u16,
}

unsafe impl Plain for Ipv4RevnatEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4AffinityKey {
    client_ip: Ipv4,
    client_cookie: u64,
    rev_nat_id: u16,
    netns_cookie: u8,
}

unsafe impl Plain for Lb4AffinityKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct LbAffinityVal {
    last_used: u64,
    backend_id: u32,
}

unsafe impl Plain for LbAffinityVal {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Lb4SrcRangeKey {
    rev_nat_id: u16,
    pad: u16,
    addr: Ipv4,
}

unsafe impl Plain for Lb4SrcRangeKey {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct LpmV4Key {
    addr: Ipv4,
}

unsafe impl Plain for LpmV4Key {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct Ipv4NatEntry {
    created: u64,
    host_local: u64,
    pad1: u64,
    pad2: u64,
    to_addr: Ipv4,
    to_port: Port,
}

unsafe impl Plain for Ipv4NatEntry {}

#[repr(C)]
#[derive(Default, TuiTable)]
pub struct IpcacheKey {
    pad0: u32,
    pad1: u16,
    cluster_id: u8,
    family: IpFamily,
    addr: Ip,
}

unsafe impl Plain for IpcacheKey {}
