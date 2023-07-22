use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Default)]
pub struct Ip {
    octets: [u8; 16],
}

impl Ip {
    pub fn ipv4(&self) -> Ipv4Addr {
        Ipv4Addr::from(<[u8; 4]>::try_from(&self.octets[..4]).unwrap())
    }

    pub fn ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.octets)
    }
}

#[derive(Default)]
pub struct IpFamily {
    family: u8,
}

const ENDPOINT_KEY_IPV4: u8 = 1;
const ENDPOINT_KEY_IPV6: u8 = 2;

impl IpFamily {
    pub fn is_ipv4(&self) -> bool {
        self.family == ENDPOINT_KEY_IPV4
    }
}

impl ToString for IpFamily {
    fn to_string(&self) -> String {
        match self.family {
            ENDPOINT_KEY_IPV4 => "ipv4",
            ENDPOINT_KEY_IPV6 => "ipv6",
            _ => "",
        }
        .to_string()
    }
}
