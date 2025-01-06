use crate::{types::Result, utils::byte_packet_buffer::BytePacketBuffer};
use std::net::Ipv4Addr;

use super::{query_class::QueryClass, query_type::QueryType};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    A {
        domain: String,
        ip_addr: Ipv4Addr,
        ttl: u32,
    },
    UNKNOWN {
        domain: String,
        qtype: QueryType,
        qclass: QueryClass,
        ttl: u32,
        rdlength: u16,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let domain = buffer.read_name()?;
        let qtype = QueryType::from_num(buffer.read_u16()?);
        let qclass = QueryClass::from_num(buffer.read_u16()?);
        let ttl = buffer.read_u32()?;
        let rdlength = buffer.read_u16()?;

        match qtype {
            QueryType::A => Ok(DnsRecord::A {
                domain: (domain),
                ip_addr: (Ipv4Addr::new(
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                )),
                ttl: (ttl),
            }),
            QueryType::UNKNOWN(_) => {
                buffer.step(rdlength as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain: domain,
                    qtype: qtype,
                    qclass: qclass,
                    ttl: ttl,
                    rdlength: rdlength,
                })
            }
        }
    }
}
