use dns_server::error::Result;
use packet::{buffer, DnsPacket};
use std::fs::File;
use std::io::Read;

fn main() -> Result<()> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = buffer::BytePacketBuffer::new();
    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer)?;
    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for rec in packet.answers {
        println!("{:#?}", rec);
    }
    for rec in packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in packet.resources {
        println!("{:#?}", rec);
    }

    Ok(())
}
