#[derive(Default)]
pub struct L4Proto {
    proto: u8,
}

impl ToString for L4Proto {
    fn to_string(&self) -> String {
        match self.proto {
            0 => "HOPOPT",
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            41 => "IPv6",
            43 => "IPv6-Route",
            44 => "IPv6-Frag",
            58 => "IPv6-ICMP",
            132 => "SCTP",
            _ => "",
        }
        .to_string()
    }
}
