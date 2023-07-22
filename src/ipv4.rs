use std::net::Ipv4Addr;
use std::string::ToString;

#[derive(Default)]
pub struct Ipv4 {
    octets: [u8; 4],
}

impl ToString for Ipv4 {
    fn to_string(&self) -> String {
        Ipv4Addr::from(self.octets).to_string()
    }
}
