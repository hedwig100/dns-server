use dns_server::error::Result;
use packet::{buffer, DnsPacket};
use server;
use std::fs::File;
use std::io::Read;
use std::net::UdpSocket;

#[allow(dead_code)]
fn read_packet() -> Result<()> {
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

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match server::handle_query(&socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
