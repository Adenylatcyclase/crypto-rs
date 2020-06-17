pub trait toBytes{
    fn to_be_bytes(&self) -> Vec<u8>;
    fn to_le_bytes(&self) -> Vec<u8>;
}