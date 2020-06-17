use std::iter::FromIterator;

pub trait ToBytes{
    fn to_bytes_be(&self) -> Vec<u8>;
    fn to_bytes_le(&self) -> Vec<u8>;
}

impl ToBytes for String {
    fn to_bytes_be(&self) -> Vec<u8>{
        self.clone().into_bytes()
    }
    fn to_bytes_le(&self) -> Vec<u8>{
        self.clone().into_bytes()
    }
}

impl ToBytes for u64 {
    fn to_bytes_be(&self) -> Vec<u8>{
        Vec::from_iter(self.to_be_bytes().iter().cloned())
    }
    fn to_bytes_le(&self) -> Vec<u8>{
        Vec::from_iter(self.to_le_bytes().iter().cloned())
    }
}

impl ToBytes for u32 {
    fn to_bytes_be(&self) -> Vec<u8>{
        Vec::from_iter(self.to_be_bytes().iter().cloned())
    }
    fn to_bytes_le(&self) -> Vec<u8>{
        Vec::from_iter(self.to_le_bytes().iter().cloned())
    }
}