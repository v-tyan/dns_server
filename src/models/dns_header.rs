// Implementation of DNS Header structure as per RFC 1035 4.1.1
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

use super::result_code::ResultCode;
use crate::types::Result;
use crate::utils::byte_packet_buffer::BytePacketBuffer;

const QR_MASK: u16 = 0b10000000_00000000;
const OPCODE_MASK: u16 = 0b01111000_00000000;
const AA_MASK: u16 = 0b00000100_00000000;
const TC_MASK: u16 = 0b00000010_00000000;
const RD_MASK: u16 = 0b00000001_00000000;
const RA_MASK: u16 = 0b00000000_10000000;
const Z_MASK: u16 = 0b00000000_01110000;
const RCODE_MASK: u16 = 0b00000000_00001111;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsHeader {
    pub id: u16,

    pub is_response: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated_message: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: u8,
    pub result_code: ResultCode,

    pub questions_count: u16,
    pub answers_count: u16,
    pub authority_records_count: u16,
    pub additional_records_count: u16,
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            is_response: false,
            opcode: 0,
            authoritative_answer: false,
            truncated_message: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            result_code: ResultCode::NOERROR,

            questions_count: 0,
            answers_count: 0,
            authority_records_count: 0,
            additional_records_count: 0,
        }
    }

    pub fn read(&mut self, bufer: &mut BytePacketBuffer) -> Result<()> {
        self.id = bufer.read_u16()?;

        let flags = bufer.read_u16()?;

        self.is_response = flags & QR_MASK > 0;
        self.opcode = ((flags & OPCODE_MASK) >> 11) as u8;
        self.authoritative_answer = flags & AA_MASK > 0;
        self.truncated_message = flags & TC_MASK > 0;
        self.recursion_desired = flags & RD_MASK > 0;
        self.recursion_available = flags & RA_MASK > 0;
        self.z = ((flags & Z_MASK) >> 4) as u8;
        self.result_code = ResultCode::from_num((flags & RCODE_MASK) as u8);

        self.questions_count = bufer.read_u16()?;
        self.answers_count = bufer.read_u16()?;
        self.authority_records_count = bufer.read_u16()?;
        self.additional_records_count = bufer.read_u16()?;

        Ok(())
    }

    pub fn write(&mut self, bufer: &mut BytePacketBuffer) -> Result<()> {
        let flags = ((self.is_response as u16) << 15)
            | ((self.opcode as u16) << 11)
            | ((self.authoritative_answer as u16) << 10)
            | ((self.truncated_message as u16) << 9)
            | ((self.recursion_desired as u16) << 8)
            | ((self.recursion_desired as u16) << 7)
            | ((self.z as u16) << 4)
            | (self.result_code as u16);

        bufer.write_u16(self.id)?;
        bufer.write_u16(flags)?;

        bufer.write_u16(self.questions_count)?;
        bufer.write_u16(self.answers_count)?;
        bufer.write_u16(self.authority_records_count)?;
        bufer.write_u16(self.additional_records_count)?;

        Ok(())
    }

    pub fn questions_count(&self) -> u16 {
        self.questions_count
    }

    pub fn answers_count(&self) -> u16 {
        self.answers_count
    }

    pub fn authority_records_count(&self) -> u16 {
        self.authority_records_count
    }

    pub fn additional_records_count(&self) -> u16 {
        self.additional_records_count
    }
}
