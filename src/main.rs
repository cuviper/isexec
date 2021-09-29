use std::env;
use std::fs;
use std::io::Read;
use std::process::exit;

const PROBE_SIZE: usize = 16;

fn check_magic(text: &[u8]) -> bool {
    match text {
        // ELF executables
        [b'\x7F', b'E', b'L', b'F', ..] => true,

        // DOS and PE executables
        [b'M', b'Z', ..] => true,

        // scripts with shebang (with absolute path)
        [b'#', b'!', b'/', ..] => true,
        [b'#', b'!', b' ', b'/', ..] => true,

        // scripts with shebang (with relative paths)
        [b'#', b'!', b'.', ..] => true,
        [b'#', b'!', b' ', b'.', ..] => true,
        [b'#', b'!', c, ..] if c.is_ascii_alphanumeric() => true,
        [b'#', b'!', b' ', c, ..] if c.is_ascii_alphanumeric() => true,

        // anything else is not a recognised executable format
        _ => false,
    }
}

fn is_executable(path: &str) -> Result<bool, String> {
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;

    let mut buf = [0u8; PROBE_SIZE];
    let len = file.read(&mut buf).map_err(|e| e.to_string())?;

    Ok(check_magic(&buf[0..len]))
}

fn main() {
    let mut args = env::args();

    let path = match (args.next(), args.next(), args.next()) {
        (_, None, None) | (_, Some(_), Some(_)) => {
            eprintln!("Accepts exactly one argument (a file path).");
            exit(1);
        },
        (_, None, Some(_)) => unreachable!(),
        (_, Some(path), None) => path,
    };

    match is_executable(&path) {
        Ok(is_exec) => {
            if is_exec {
                println!("isexec");
            } else {
                println!("unexec");
            }
        },
        Err(error) => {
            eprintln!("Error: {}", error);
            exit(2);
        },
    }
}

#[cfg(test)]
mod tests {
    use super::is_executable;
    use super::check_magic;

    #[test]
    fn valid_shebangs() {
        assert!(check_magic(b"#!/bin/sh"));
        assert!(check_magic(b"#!/bin/bash"));
        assert!(check_magic(b"#!/bin/false"));
        assert!(check_magic(b"#!/usr/bin/python3"));
        assert!(check_magic(b"#! /usr/bin/python3"));
        assert!(check_magic(b"#!/usr/bin/env python"));
        assert!(check_magic(b"#! /usr/bin/env python"));
        assert!(check_magic(b"#!./build/program"));
        assert!(check_magic(b"#! program"));
        assert!(check_magic(b"#!../../usr/bin/python3"));
    }

    #[test]
    fn invalid_shebangs() {
        assert!(!check_magic(b""));
        assert!(!check_magic(b"#!"));
        assert!(!check_magic(b"#! "));
        assert!(!check_magic(b"#![no_std]"));
        assert!(!check_magic(b"#![deny(warnings)]"));
        assert!(!check_magic(b"#[use_macros]"));
        assert!(!check_magic(b"#!@?%!"));
    }

    #[test]
    fn valid_executables() {
        assert!(is_executable("/usr/bin/cp").unwrap());
        assert!(is_executable("/usr/bin/env").unwrap());
        assert!(is_executable("/usr/bin/mv").unwrap());
        assert!(is_executable("/usr/bin/egrep").unwrap());
        assert!(is_executable("/usr/bin/fgrep").unwrap());
        assert!(is_executable("/usr/bin/ldd").unwrap());
        assert!(is_executable("/usr/bin/pkg-config").unwrap());
    }

    #[test]
    fn invalid_executables() {
        assert!(!is_executable("./src/main.rs").unwrap());
        assert!(!is_executable("/etc/fstab").unwrap());
        assert!(!is_executable("/etc/group").unwrap());
    }
}
