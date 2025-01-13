use models::{
    dns_packet::DnsPacket, dns_question::DnsQuestion, query_class::QueryClass,
    query_type::QueryType,
};
use utils::byte_packet_buffer::BytePacketBuffer;

use crate::types::Result;
use std::{fs::File, io::Read, net::UdpSocket, time::Duration};
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod types;
#[allow(dead_code)]
mod utils;
fn main() -> Result<()> {
    let qname = "yahoo.com";
    let qtype = QueryType::MX;
    let qclass = QueryClass::IN;

    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;
    socket.set_read_timeout(Some(Duration::new(5, 0)))?;

    let mut req_buffer = BytePacketBuffer::new();
    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions_count = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype, qclass));

    packet.to_buffer(&mut req_buffer)?;

    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;
    let mut res_buffer = BytePacketBuffer::new();

    socket.recv_from(&mut res_buffer.buf)?;

    let res_packet = DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet);

    Ok(())
}

fn print_hexdump(buffer: &[u8; 512]) {
    for (i, byte) in buffer.iter().enumerate() {
        // Print the address (offset) every 16 bytes
        if i % 16 == 0 {
            // Print the address in hexadecimal format
            print!("{:04x}: ", i);
        }

        // Print the byte in hexadecimal format
        print!("{:02x} ", byte);

        // Print a newline after every 16 bytes
        if i % 16 == 15 {
            println!();
        }
    }

    // Print a newline if the last line isn't complete
    if buffer.len() % 16 != 0 {
        println!();
    }
}
