use std::net::Ipv6Addr;
use std::string::ToString;

#[derive(Default)]
pub struct Ipv6 {
    octets: [u8; 16],
}

impl ToString for Ipv6 {
    fn to_string(&self) -> String {
        Ipv6Addr::from(self.octets).to_string()
    }
}
