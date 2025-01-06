use models::dns_packet::DnsPacket;
use utils::byte_packet_buffer::BytePacketBuffer;

use crate::types::Result;
use std::{fs::File, io::Read};
#[allow(dead_code)]
mod models;
#[allow(dead_code)]
mod types;
#[allow(dead_code)]
mod utils;
fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet);

    Ok(())
}
