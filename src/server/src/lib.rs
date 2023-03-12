mod error;

use error::Result;
use packet;
use packet::buffer;
use packet::header;
use packet::query;
use std::net;
use std::net::UdpSocket;

fn lookup(
    qname: &str,
    qtype: query::QueryType,
    server: (net::Ipv4Addr, u16),
) -> Result<packet::DnsPacket> {
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

    packet::DnsPacket::from_buffer(&mut res_buffer)
}

fn recursive_lookup(qname: &str, qtype: query::QueryType) -> Result<packet::DnsPacket> {
    // For now we're alwasy starting with *a.root-servers.net*.
    let mut ns = "198.41.0.4".parse::<net::Ipv4Addr>().unwrap();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns;
        let server = (ns_copy, 53);
        let response = lookup(qname, qtype, server)?;

        if !response.answers.is_empty() && response.header.rescode == header::ResultCode::NOERROR {
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

        let recursive_response = recursive_lookup(&new_ns_name, query::QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns;
        } else {
            return Ok(response);
        }
    }
}

pub fn handle_query(socket: &UdpSocket) -> Result<()> {
    let mut req_buffer = buffer::BytePacketBuffer::new();

    let (_, src) = socket.recv_from(&mut req_buffer.buf)?;

    let mut request = packet::DnsPacket::from_buffer(&mut req_buffer)?;

    let mut pkt = packet::DnsPacket::new();
    pkt.header.id = request.header.id;
    pkt.header.recursion_desired = true;
    pkt.header.recursion_available = true;
    pkt.header.response = true;

    if let Some(question) = request.questions.pop() {
        println!("Received query: {:?}", question);

        if let Ok(result) = recursive_lookup(&question.name, question.qtype) {
            pkt.questions.push(question);
            pkt.header.rescode = result.header.rescode;

            for rec in result.answers {
                println!("Answer: {:?}", rec);
                pkt.answers.push(rec);
            }
            for rec in result.authorities {
                println!("Authority: {:?}", rec);
                pkt.authorities.push(rec);
            }
            for rec in result.resources {
                println!("Resource: {:?}", rec);
                pkt.resources.push(rec);
            }
        }
    } else {
        pkt.header.rescode = header::ResultCode::SERVFAIL;
    }

    let mut res_buffer = buffer::BytePacketBuffer::new();
    pkt.write(&mut res_buffer)?;

    let len = res_buffer.pos();
    let data = res_buffer.get_range(0, len)?;
    socket.send_to(data, src)?;

    Ok(())
}
