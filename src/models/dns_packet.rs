use super::{
    dns_header::DnsHeader, dns_question::DnsQuestion, dns_record::DnsRecord,
    query_class::QueryClass, query_type::QueryType,
};
use crate::types::Result;
use crate::utils::byte_packet_buffer::BytePacketBuffer;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
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
}
