pub trait TuiTable {
    fn header() -> Vec<&'static str>;
    fn row(&self) -> Vec<String>;
}
