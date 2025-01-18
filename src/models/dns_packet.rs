use std::net::Ipv4Addr;

use rand::seq::SliceRandom;
use rand::thread_rng;

use super::{
    dns_header::DnsHeader, dns_question::DnsQuestion, dns_record::DnsRecord,
    query_class::QueryClass, query_type::QueryType,
};
use crate::types::Result;
use crate::utils::byte_packet_buffer::BytePacketBuffer;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut dns_packet = DnsPacket::new();
        dns_packet.header.read(buffer)?;

        for _ in 0..dns_packet.header.questions_count() {
            let mut question = DnsQuestion::new(
                "".to_string(),
                QueryType::UNKNOWN(0),
                QueryClass::UNKNOWN(0),
            );
            question.read(buffer)?;
            dns_packet.questions.push(question);
        }

        for _ in 0..dns_packet.header.answers_count() {
            let rec = DnsRecord::read(buffer)?;
            dns_packet.answers.push(rec);
        }
        for _ in 0..dns_packet.header.authority_records_count() {
            let rec = DnsRecord::read(buffer)?;
            dns_packet.authorities.push(rec);
        }
        for _ in 0..dns_packet.header.additional_records_count() {
            let rec = DnsRecord::read(buffer)?;
            dns_packet.additionals.push(rec);
        }

        Ok(dns_packet)
    }

    pub fn to_buffer(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.write(buffer)?;
        for record in &self.questions {
            record.write(buffer)?;
        }
        for record in &self.answers {
            record.write(buffer)?;
        }
        for record in &self.authorities {
            record.write(buffer)?;
        }
        for record in &self.additionals {
            record.write(buffer)?;
        }

        Ok(())
    }

    pub fn get_random_a(&self) -> Option<Ipv4Addr> {
        let a_records: Vec<Ipv4Addr> = self
            .answers
            .iter()
            .filter_map(|record| match record {
                DnsRecord::A { ip_v4_addr, .. } => Some(*ip_v4_addr),
                _ => None,
            })
            .collect();

        let mut rng = thread_rng();
        a_records.choose(&mut rng).copied()
    }

    fn get_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities
            .iter()
            .filter_map(|record| match record {
                DnsRecord::NS { domain, host, .. } => Some((domain.as_str(), host.as_str())),
                _ => None,
            })
            .filter(move |(domain, _)| qname.ends_with(*domain))
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        self.get_ns(qname)
            .flat_map(|(_, host)| {
                self.additionals
                    .iter()
                    .filter_map(move |record| match record {
                        DnsRecord::A {
                            domain, ip_v4_addr, ..
                        } if domain == host => Some(ip_v4_addr),
                        _ => None,
                    })
            })
            .map(|addr| *addr)
            .next()
    }

    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.get_ns(qname).map(|(_, host)| host).next()
    }
}
