// 🌐 Simple DNS Resolver in Pure Rust
// -----------------------------------
// This is a tiny DNS resolver that sends a DNS query over UDP
// and prints the response — specifically the A records (IPv4 addresses).
//
// It avoids any dependencies other than `clap` (for CLI) and `std`.
// No fancy crates like `trust-dns`, just raw socket work and manual DNS parsing!
// This is perfect if you're learning networking or DNS protocol basics.
//
// Run it like this:
// $ cargo run -- google.com
//
// Or build it and run the binary:
// $ ./dns-resolver github.com

use std::net::UdpSocket;
use std::time::Duration;
use clap::Parser;

// 🧾 Command line argument parser using `clap`
#[derive(Parser, Debug)]
#[command(author, version, about = "A DNS resolver built in pure Rust", long_about = None)]
struct Args {
    /// Just give the domain name you want to resolve. Example: example.com
    domain: String,
}

// 🧠 Represents the DNS header section (first 12 bytes in a DNS packet)
struct DnsHeader {
    id: u16,       // Just a random ID to match requests with responses
    flags: u16,    // Set bits for things like recursion, query/response
    qdcount: u16,  // Number of questions (usually 1)
    ancount: u16,  // Number of answers (set to 0 when sending)
    nscount: u16,  // Number of authority records (also 0 for basic query)
    arcount: u16,  // Number of additional records (also 0)
}

// 🎯 Convert the header into bytes to send over the network
impl DnsHeader {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.id.to_be_bytes());
        bytes.extend(&self.flags.to_be_bytes());
        bytes.extend(&self.qdcount.to_be_bytes());
        bytes.extend(&self.ancount.to_be_bytes());
        bytes.extend(&self.nscount.to_be_bytes());
        bytes.extend(&self.arcount.to_be_bytes());
        bytes
    }
}

// ❓ The question part of DNS request (what you're asking for)
struct DnsQuestion {
    qname: String, // The domain name, like "google.com"
    qtype: u16,    // What kind of record you want (1 = A record = IPv4 address)
    qclass: u16,   // 1 means Internet (IN)
}

// 🔧 Convert the domain name into the wire format, e.g., google.com → 6google3com0
impl DnsQuestion {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for label in self.qname.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend(label.as_bytes());
        }
        bytes.push(0); // Ends the QNAME
        bytes.extend(&self.qtype.to_be_bytes());
        bytes.extend(&self.qclass.to_be_bytes());
        bytes
    }
}

// 🧩 Helper to decode domain names from the response, including compression pointers
fn decode_name(buf: &[u8], mut offset: usize) -> (String, usize) {
    let mut labels = Vec::new();
    let mut jumped = false;
    let orig_offset = offset;

    while offset < buf.len() {
        let len = buf[offset];
        // 💡 Pointers start with two 1 bits: 0b11xxxxxx
        if len & 0b1100_0000 == 0b1100_0000 {
            let b2 = buf[offset + 1] as usize;
            let pointer = (((len & 0b0011_1111) as usize) << 8) | b2;
            if !jumped {
                jumped = true;
            }
            offset = pointer;
            continue;
        }

        if len == 0 {
            offset += 1;
            break;
        }

        let start = offset + 1;
        let end = start + len as usize;
        labels.push(String::from_utf8_lossy(&buf[start..end]).to_string());
        offset = end;
    }

    let name = labels.join(".");
    let new_offset = if jumped { orig_offset + 2 } else { offset };
    (name, new_offset)
}

// 📦 Parse the DNS response and print out A records (IPv4)
fn parse_response(buf: &[u8], length: usize) {
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    println!("\n✅ Answer Count: {ancount}");

    let mut i = 12;
    let (_qname, after_qname) = decode_name(buf, i);
    i = after_qname + 4; // Skip QTYPE + QCLASS

    for _ in 0..ancount {
        let (name, after_name) = decode_name(buf, i);
        i = after_name;

        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let class = u16::from_be_bytes([buf[i + 2], buf[i + 3]]);
        let ttl   = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;

        let data = &buf[i..i + rdlen];
        i += rdlen;

        println!("- Name : {name}");
        println!("  Type : {rtype}  Class : {class}  TTL : {ttl}");

        if rtype == 1 && rdlen == 4 {
            // A record — IPv4
            println!("  Data : {}.{}.{}.{}",
                     data[0], data[1], data[2], data[3]);
        } else {
            print!("  Data :");
            for b in data {
                print!(" {:02X}", b);
            }
            println!();
        }
    }
}

// 🚀 Main program: put everything together
fn main() -> std::io::Result<()> {
    let args = Args::parse(); // CLI parsing

    println!("\n🌐 Querying {} (Type A)...", args.domain);

    // 🧱 Build the DNS query
    let header = DnsHeader {
        id: 0x1234,        // Just a random number
        flags: 0x0100,     // Standard query with recursion desired
        qdcount: 1,        // One question
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };

    let question = DnsQuestion {
        qname: args.domain,
        qtype: 1, // A record
        qclass: 1, // IN (Internet)
    };

    let mut packet = Vec::new();
    packet.extend(header.to_bytes());
    packet.extend(question.to_bytes());

    // 🔌 Open a UDP socket and talk to Google DNS (8.8.8.8)
    let socket = UdpSocket::bind("0.0.0.0:0")?; // use any available port
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    socket.send_to(&packet, "8.8.8.8:53")?;

    // 📥 Receive the response
    let mut buf = [0u8; 512]; // standard DNS packet size
    let (amt, _) = socket.recv_from(&mut buf)?;

    parse_response(&buf, amt);

    Ok(())
}
