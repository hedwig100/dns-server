use crate::buffer;
use crate::error::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
}

impl From<&QueryType> for u16 {
    fn from(q: &QueryType) -> u16 {
        match *q {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
        }
    }
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut buffer::BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16(); // class

        Ok(())
    }
}
