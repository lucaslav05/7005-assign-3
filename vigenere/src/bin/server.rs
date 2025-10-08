use libc::{_exit};
use nix::sys::socket::recv;
use nix::sys::socket::{socket, Backlog, SockaddrStorage};
use nix::{
    errno::Errno,
    sys::{
        signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
        socket::{
            accept, bind, getpeername, listen, send, AddressFamily, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
        },
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{close, fork, ForkResult},
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{env, process};
use std::{str::FromStr};
use serde::Deserialize;
use Signal::SIGCHLD;

///sighandler to handle child processes
extern "C" fn sigchld_handler(_signal: libc::c_int) {
    while let Ok(WaitStatus::StillAlive) = waitpid(None, Some(WaitPidFlag::WNOHANG)) {}
}

///struct used to deserialize message from the client
#[derive(Deserialize)]
struct VigMsg { 
        message: String,
        encrypt_key: String,  
}

/**
main function to act as the driver for the server
**/
fn main() {

    let (ip, port) = parse_args();
    let sock = create_socket(ip, port);

    listen_for_connections(&sock);

    let handler = SigHandler::Handler(sigchld_handler);
    let sa = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(SIGCHLD, &sa).expect("server: sigaction failed");
    };

    println!("server: waiting for connections...");
    loop {
        let session_sock = accept_client(&sock);

        match unsafe { fork() }.expect("server: fork failed") {
            ForkResult::Child => {
                close_socket(&sock);

                let incoming = receive_message(&session_sock);

                let key = incoming.encrypt_key.as_bytes();
                let msg = encrypt_message(incoming.message.as_bytes(), &key);

                send_message(&session_sock, &msg);

                close_socket(&session_sock);
                unsafe { _exit(0) }
            }
            _ => drop(session_sock),
        }
    }
}

/**
function used to parse command line arguments
**/
fn parse_args() -> (String, String) {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: server ip port");
        process::exit(1);
    }

    let ip = args[1].clone();
    let port = args[2].clone();

    (ip, port)
}

/**
function used to create domain socket
**/
fn create_socket(ip: String, port: String) -> OwnedFd {
    let addr_str = format!("{}:{}", ip, port);

    // Try IPv4 first
    if let Ok(sockaddr_v4) = SockaddrIn::from_str(&addr_str) {
        let sock = socket(AddressFamily::Inet, SockType::Stream, SockFlag::empty(), None)
            .expect("create_socket: failed to create IPv4 socket");
        bind(sock.as_raw_fd(), &sockaddr_v4).expect("create_socket: bind failed (IPv4)");
        println!("Server bound to IPv4 address {}", addr_str);
        sock
    }
    // Then try IPv6
    else if let Ok(sockaddr_v6) = SockaddrIn6::from_str(&addr_str) {
        let sock = socket(AddressFamily::Inet6, SockType::Stream, SockFlag::empty(), None)
            .expect("create_socket: failed to create IPv6 socket");
        bind(sock.as_raw_fd(), &sockaddr_v6).expect("create_socket: bind failed (IPv6)");
        println!("Server bound to IPv6 address {}", addr_str);
        sock
    }
    // Neither IPv4 nor IPv6 worked
    else {
        eprintln!("create_socket: invalid or unsupported IP '{}'", ip);
        process::exit(1);
    }
}

/**
function to listen for clients
**/
fn listen_for_connections(sock: &OwnedFd) {
    let backlog = Backlog::new(10).unwrap();
    listen(sock, backlog).expect("server listen failed");
}

/**
function used to accept clients
**/
fn accept_client(sock: &OwnedFd) -> OwnedFd {
    loop {
        match accept(sock.as_raw_fd()) {
            Err(Errno::EINTR) => continue,
            Ok(raw_fd) => {
                if let Ok(_saddr) = getpeername::<SockaddrStorage>(raw_fd) {
                    println!("server: got connection from client");
                }
                return unsafe { OwnedFd::from_raw_fd(raw_fd) };
            }
            _ => panic!("server: accept failed"),
        }
    }
}

/**
function used to get message struct from the client
**/
fn receive_message(sock: &OwnedFd) -> VigMsg {
    let mut buf = [0u8; 1024];
    let nbytes = recv(sock.as_raw_fd(), &mut buf, MsgFlags::empty())
        .expect("server: receive failed");

    let data = &buf[..nbytes];
    serde_json::from_slice(data).expect("server: failed to parse JSON")
}
 
/**
function used to apply Vigenere cipher based on key to message
**/
fn encrypt_message(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut key_index = 0;
    let key_len = key.len();

    for c in msg {
        // preserve spaces and non-alphabetic chars
        if !c.is_ascii_alphabetic() {
            result.push(*c);
            continue;
        }

        // determine shift value based on key letter
        let key_char = key[key_index % key_len];
        let shift = if key_char.is_ascii_uppercase() {
            key_char - b'A'
        } else if key_char.is_ascii_lowercase() {
            key_char - b'a'
        } else {
            0
        };

        // apply shift to character
        let encrypted = if c.is_ascii_uppercase() {
            ((c - b'A' + shift) % 26) + b'A'
        } else {
            ((c - b'a' + shift) % 26) + b'a'
        };

        result.push(encrypted);
        key_index += 1;
    }

    result
}

/**
function used to send message to client
**/
fn send_message(sock: &OwnedFd, msg: &[u8]) {
    send(sock.as_raw_fd(), msg, MsgFlags::empty()).expect("server: send failed");
}

/**
function to close socket
**/
fn close_socket(sock: &OwnedFd) {
    close(sock.as_raw_fd()).expect("server: close failed");
}
