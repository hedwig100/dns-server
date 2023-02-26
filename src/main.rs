use dns_server::error::Result;
use packet::query;
use packet::{buffer, DnsPacket};
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
    let qname = "google.com";
    let qtype = query::QueryType::A;

    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = packet::DnsPacket::new();

    packet.header.id = 6666;
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(query::DnsQuestion::new(qname.to_string(), qtype));

    let mut req_buffer = buffer::BytePacketBuffer::new();
    packet.write(&mut req_buffer)?;

    socket.send_to(&req_buffer.buf[0..req_buffer.pos], server)?;

    let mut res_buffer = buffer::BytePacketBuffer::new();
    socket.recv_from(&mut res_buffer.buf)?;

    let res_packet = packet::DnsPacket::from_buffer(&mut res_buffer)?;
    println!("{:#?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:#?}", q);
    }
    for rec in res_packet.answers {
        println!("{:#?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:#?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:#?}", rec);
    }
    Ok(())
}
