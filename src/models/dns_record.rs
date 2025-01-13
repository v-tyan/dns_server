use crate::{types::Result, utils::byte_packet_buffer::BytePacketBuffer};
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{query_class::QueryClass, query_type::QueryType};

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    A {
        domain: String,
        ip_v4_addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        host: String,
        ttl: u32,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        ip_v6_addr: Ipv6Addr,
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
                ip_v4_addr: (Ipv4Addr::new(
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                    buffer.read_u8()?,
                )),
                ttl: (ttl),
            }),
            QueryType::NS => Ok(DnsRecord::NS {
                domain: domain,
                host: buffer.read_name()?,
                ttl: ttl,
            }),
            QueryType::CNAME => Ok(DnsRecord::CNAME {
                domain: domain,
                host: buffer.read_name()?,
                ttl: ttl,
            }),
            QueryType::MX => Ok(DnsRecord::MX {
                domain: domain,
                priority: buffer.read_u16()?,
                host: buffer.read_name()?,
                ttl: ttl,
            }),
            QueryType::AAAA => Ok(DnsRecord::AAAA {
                domain: domain,
                ip_v6_addr: Ipv6Addr::new(
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                    buffer.read_u16()?,
                ),
                ttl: ttl,
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

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match self {
            DnsRecord::A {
                domain,
                ip_v4_addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(4)?;

                buffer.write_u32(ip_v4_addr.to_bits())?;
            }
            DnsRecord::NS { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME { domain, host, ttl } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(*ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA {
                domain,
                ip_v6_addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(QueryClass::IN.to_num())?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(16)?;

                for segment in ip_v6_addr.segments() {
                    buffer.write_u16(segment)?;
                }
            }
            DnsRecord::UNKNOWN {
                domain,
                qtype,
                qclass,
                ttl,
                rdlength,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(qtype.to_num())?;
                buffer.write_u16(qclass.to_num())?;
                buffer.write_u32(*ttl)?;
                buffer.write_u16(*rdlength)?;
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}
