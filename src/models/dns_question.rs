use super::query_class::QueryClass;
use super::query_type::QueryType;
use crate::types::Result;
use crate::utils::byte_packet_buffer::BytePacketBuffer;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType, qclass: QueryClass) -> DnsQuestion {
        DnsQuestion {
            name: name,
            qtype: qtype,
            qclass: qclass,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.name = buffer.read_name()?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        self.qclass = QueryClass::from_num(buffer.read_u16()?);

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(self.qclass.to_num())?;

        Ok(())
    }
}
