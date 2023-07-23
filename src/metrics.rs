#[repr(C)]
#[derive(Default)]
pub struct MetricsReason {
    reason: u8,
}

#[repr(C)]
#[derive(Default)]
pub struct MetricsDir {
    dir: u8,
}

impl ToString for MetricsReason {
    fn to_string(&self) -> String {
        match self.reason {
            0 => "REASON_FORWARDED",
            3 => "REASON_PLAINTEXT",
            4 => "REASON_DECRYPT",
            5 => "REASON_LB_NO_BACKEND_SLOT",
            6 => "REASON_LB_NO_BACKEND",
            7 => "REASON_LB_REVNAT_UPDATE",
            8 => "REASON_LB_REVNAT_STALE",
            9 => "REASON_FRAG_PACKET",
            10 => "REASON_FRAG_PACKET_UPDATE",
            11 => "REASON_MISSED_CUSTOM_CALL",
            // DROP
            130 => "DROP_UNUSED1",
            131 => "DROP_UNUSED2",
            132 => "DROP_INVALID_SIP",
            133 => "DROP_POLICY",
            134 => "DROP_INVALID",
            135 => "DROP_CT_INVALID_HDR",
            136 => "DROP_FRAG_NEEDED",
            137 => "DROP_CT_UNKNOWN_PROTO",
            138 => "DROP_UNUSED4",
            139 => "DROP_UNKNOWN_L3",
            140 => "DROP_MISSED_TAIL_CALL",
            141 => "DROP_WRITE_ERROR",
            142 => "DROP_UNKNOWN_L4",
            143 => "DROP_UNKNOWN_ICMP_CODE",
            144 => "DROP_UNKNOWN_ICMP_TYPE",
            145 => "DROP_UNKNOWN_ICMP6_CODE",
            146 => "DROP_UNKNOWN_ICMP6_TYPE",
            147 => "DROP_NO_TUNNEL_KEY",
            148 => "DROP_UNUSED5",
            149 => "DROP_UNUSED6",
            150 => "DROP_UNKNOWN_TARGET",
            151 => "DROP_UNROUTABLE",
            152 => "DROP_UNUSED7",
            153 => "DROP_CSUM_L3",
            154 => "DROP_CSUM_L4",
            155 => "DROP_CT_CREATE_FAILED",
            156 => "DROP_INVALID_EXTHDR",
            157 => "DROP_FRAG_NOSUPPORT",
            158 => "DROP_NO_SERVICE",
            159 => "DROP_UNUSED8",
            160 => "DROP_NO_TUNNEL_ENDPOINT",
            161 => "DROP_NAT_46X64_DISABLED",
            162 => "DROP_EDT_HORIZON",
            163 => "DROP_UNKNOWN_CT",
            164 => "DROP_HOST_UNREACHABLE",
            165 => "DROP_NO_CONFIG",
            166 => "DROP_UNSUPPORTED_L2",
            167 => "DROP_NAT_NO_MAPPING",
            168 => "DROP_NAT_UNSUPP_PROTO",
            169 => "DROP_NO_FIB",
            170 => "DROP_ENCAP_PROHIBITED",
            171 => "DROP_INVALID_IDENTITY",
            172 => "DROP_UNKNOWN_SENDER",
            173 => "DROP_NAT_NOT_NEEDED",
            174 => "DROP_IS_CLUSTER_IP",
            175 => "DROP_FRAG_NOT_FOUND",
            176 => "DROP_FORBIDDEN_ICMP6",
            177 => "DROP_NOT_IN_SRC_RANGE",
            178 => "DROP_PROXY_LOOKUP_FAILED",
            179 => "DROP_PROXY_SET_FAILED",
            180 => "DROP_PROXY_UNKNOWN_PROTO",
            181 => "DROP_POLICY_DENY",
            182 => "DROP_VLAN_FILTERED",
            183 => "DROP_INVALID_VNI",
            184 => "DROP_INVALID_TC_BUFFER",
            185 => "DROP_NO_SID",
            186 => "DROP_MISSING_SRV6_STATE",
            187 => "DROP_NAT46",
            188 => "DROP_NAT64",
            189 => "DROP_POLICY_AUTH_REQUIRED",
            190 => "DROP_CT_NO_MAP_FOUND",
            191 => "DROP_SNAT_NO_MAP_FOUND",
            192 => "DROP_INVALID_CLUSTER_ID",
            193 => "DROP_DSR_ENCAP_UNSUPP_PROTO",
            194 => "DROP_NO_EGRESS_GATEWAY",
            195 => "DROP_UNENCRYPTED_TRAFFIC",
            100 => "NAT_46X64_RECIRC",
            _ => "",
        }
        .to_string()
    }
}

impl ToString for MetricsDir {
    fn to_string(&self) -> String {
        match self.dir {
            1 => "INGRESS",
            2 => "EGRESS",
            3 => "SERVICE",
            _ => "",
        }
        .to_string()
    }
}
