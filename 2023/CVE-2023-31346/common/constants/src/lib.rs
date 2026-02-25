//! This crate contains constants shared between the kernel, loader and host executable.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub const LOG_PORT: u16 = 0x3f8;
