use libc::{_exit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{env, process};
use std::{str::FromStr};
use serde::Deserialize;
use Signal::SIGCHLD;
use std::net::TcpListener;
use polling::{Event, Events, Poller};

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

    let key = 7;    

    let (ip, port) = parse_args();
    let sock = create_socket(ip, port);

    let handler = SigHandler::Handler(sigchld_handler);
    let sa = SigAction::new(handler, SaFlags::empty(), SigSet::empty());
    unsafe {
        sigaction(SIGCHLD, &sa).expect("server: sigaction failed");
    };

    println!("server: waiting for connections...");

    for stream in sock.incoming() {
        match stream {
            Ok(stream) => {
                let msg_in = receive_message(&stream.as_raw_rd());

                let key = msg_in.encrypt_key.as_bytes();
                let msg = encrypt_message(msg_in.message.as_bytes(), &key);

                send_message(&stream.as_raw_fd, &msg);

                close_socket(stream.as_raw_fd());
            }
            Err(e) => {//Connection failed}
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
fn create_socket(ip: String, port: String) -> TcpListener {
    if ip.contains(':') {
        let addr_str = format!("[{}]:{}", ip, port);
        let socket = TcpListener::bind(addr_str).unwrap();
        socket.set_nonblocking(true);
        
        socket
    } else {
        let addr_str = format!("{}:{}", ip, port);
        let socket = TcpListener::bind(addr_str).unwrap();
        socket.set_nonblocking(true);

        socket
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
