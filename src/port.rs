#[derive(Default)]
pub struct Port {
    port: u16,
}

impl ToString for Port {
    fn to_string(&self) -> String {
        u16::from_be(self.port).to_string()
    }
}
