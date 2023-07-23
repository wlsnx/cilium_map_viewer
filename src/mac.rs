use std::string::ToString;

#[derive(Default)]
pub struct Mac {
    octets: [u8; 6],
}

impl ToString for Mac {
    fn to_string(&self) -> String {
        let hex: Vec<_> = self.octets.iter().map(|n| format!("{:02x}", n)).collect();
        hex.join(":")
    }
}
