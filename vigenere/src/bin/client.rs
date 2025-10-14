use nix::sys::socket::send;
use nix::{
    sys::socket::{
        connect, recv, socket, AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6
    },
    unistd::close,
};
use serde::Serialize;
use std::os::fd::{AsRawFd, OwnedFd};
use std::{env, process};
use std::{str::FromStr};

///Struct to store message and shift value to send to server
#[derive(Serialize)]
struct VigMsg { 
        message: String,
        encrypt_key: String,  
}

/**
Main function to act as the driver for the client
**/
fn main() {
    let (ip_addr, port, key, msg) = parse_args();

    let client_msg = VigMsg {
        message: msg,
        encrypt_key: key,  
    };

    let sock = create_socket(&ip_addr, &port);

    connect_to_server(&sock, &ip_addr, &port);

    send_message(&sock, &client_msg);

    let mut buf = vec![0; client_msg.message.len()];
    receive_message(&sock, &mut buf);

    if let Ok(response) = std::str::from_utf8(&buf) {
        println!("Encrypted Message: {}", response);
        let decrypt_msg = String::from_utf8(decrypt_message(response.as_bytes(), client_msg.encrypt_key.as_bytes())).unwrap();
        println!("Decrypted Message: {}", decrypt_msg);
    }

    close_socket(sock);
}

/**
function used to parse command line arguments
**/
fn parse_args() -> (String, String, String, String) {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: client ip port key message");
        process::exit(1);
    }

    let ip = args[1].clone();
    let port = args[2].clone();
    let key = args[3].clone();
    let message = args[4].clone();


    (ip, port, key, message)
}

/**
function to create network socket
**/
fn create_socket(ip: &str, port: &str) -> OwnedFd {
    // If the address looks like IPv6, wrap in []
    let addr_str = if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }; 

    // Try IPv4 first
    if SockaddrIn::from_str(&addr_str).is_ok() {
        let sock = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)
            .expect("create_socket: failed to create IPv4 socket");
        println!("Client created IPv4 socket for {}", addr_str);
        sock
    }
    // Then try IPv6
    else if SockaddrIn6::from_str(&addr_str).is_ok() {
        let sock = socket(AddressFamily::Inet6, SockType::Stream, SockFlag::empty(), None)
            .expect("create_socket: failed to create IPv6 socket");
        println!("Client created IPv6 socket for {}", addr_str);
        sock
    }
    // Neither worked
    else {
        eprintln!("create_socket: invalid or unsupported IP '{}'", ip);
        process::exit(1);
    }
}


/**
function to connect to the server using the network socket
**/
fn connect_to_server(sock: &OwnedFd, ip: &str, port: &str) {
   let addr_str = if ip.contains(':') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };  

    // Try IPv4 first
    if let Ok(sockaddr_v4) = SockaddrIn::from_str(&addr_str) {
        connect(sock.as_raw_fd(), &sockaddr_v4).expect("connect_to_server: IPv4 connect failed");
        println!("Connected to IPv4 server at {}", addr_str);
    }
    // Then try IPv6
    else if let Ok(sockaddr_v6) = SockaddrIn6::from_str(&addr_str) {
        connect(sock.as_raw_fd(), &sockaddr_v6).expect("connect_to_server: IPv6 connect failed");
        println!("Connected to IPv6 server at {}", addr_str);
    }
    // If neither works, exit with error
    else {
        eprintln!("connect_to_server: Invalid or unsupported IP address '{}'", ip);
        process::exit(1);
    }
}

/**
function to send message struct to server
**/
fn send_message(sock: &OwnedFd, msg: &VigMsg) {
    let bytes = serde_json::to_vec(msg).expect("Failed to serialize message");
    let bytes_sent = send(sock.as_raw_fd(), &bytes, MsgFlags::empty())
        .expect("send_message: send failed");
    println!("Sent {} bytes", bytes_sent);
}

/**
function to receive message from the server
**/
fn receive_message(sock: &OwnedFd, buf: &mut [u8]){
    let bytes_read = recv(sock.as_raw_fd(), buf, MsgFlags::empty())
        .expect("send_message: recv failed");
    println!("Received {} bytes", bytes_read);
}

/**
Function used to reverse the Vigenere cipher encryption applied to the message
**/
fn decrypt_message(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut key_index = 0;
    let key_len = key.len();

    for c in msg {
        // preserve non-alphabetic chars
        if !c.is_ascii_alphabetic() {
            result.push(*c);
            continue;
        }

        // determine shift from key
        let key_char = key[key_index % key_len];
        let shift = if key_char.is_ascii_uppercase() {
            key_char - b'A'
        } else if key_char.is_ascii_lowercase() {
            key_char - b'a'
        } else {
            0
        };

        // reverse the shift
        let decrypted = if c.is_ascii_uppercase() {
            ((c - b'A' + 26 - shift) % 26) + b'A'
        } else {
            ((c - b'a' + 26 - shift) % 26) + b'a'
        };

        result.push(decrypted);
        key_index += 1;
    }

    result
}

/**
function used to close socket
**/
fn close_socket(sock: OwnedFd) {
    close(sock).expect("close_socket: failed to close socket");
}
