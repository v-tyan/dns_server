use models::{
    dns_packet::DnsPacket, dns_question::DnsQuestion, query_class::QueryClass,
    query_type::QueryType, result_code::ResultCode,
};
use utils::byte_packet_buffer::BytePacketBuffer;

use crate::types::Result;
use std::net::{Ipv4Addr, UdpSocket};
mod models;
mod types;
mod utils;

fn lookup(
    qname: &str,
    qtype: QueryType,
    qclass: QueryClass,
    server: (Ipv4Addr, u16),
) -> Result<DnsPacket> {
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions_count = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype, qclass));

    let mut req_buffer = BytePacketBuffer::new();
    packet.to_buffer(&mut req_buffer)?;
    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: QueryType, qclass: QueryClass) -> Result<DnsPacket> {
    let mut ns = "198.41.0.4".parse::<Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;

        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, qclass, server)?;

        if !response.answers.is_empty() && response.header.result_code == ResultCode::NOERROR {
            return Ok(response);
        }

        if response.header.result_code == ResultCode::NXDOMAIN {
            return Ok(response);
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns;

            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response),
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A, QueryClass::IN)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = DnsPacket::from_buffer(&mut req_buffer)?;

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.is_response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.qtype, question.qclass) {
            packet.questions.push(question);
            packet.header.result_code = result.header.result_code;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                packet.authorities.push(rec);
            }
            for rec in result.additionals {
                println!("Resource: {:?}", rec);
                packet.additionals.push(rec);
            }

            packet.header.questions_count = packet.questions.len() as u16;
            packet.header.answers_count = packet.answers.len() as u16;
            packet.header.authority_records_count = packet.authorities.len() as u16;
            packet.header.additional_records_count = packet.additionals.len() as u16;
        } else {
            packet.header.result_code = ResultCode::SERVFAIL;
        }
    } else {
        packet.header.result_code = ResultCode::FORMERR;
    }

    print!("{:#?}", packet);
    let mut res_buffer = BytePacketBuffer::new();
    packet.to_buffer(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;

    socket.send_to(data, src)?;

    Ok(())
}

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
