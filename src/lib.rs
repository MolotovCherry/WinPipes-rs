mod client;
mod server;

use std::ops::Deref;

pub use client::*;
pub use server::*;
use windows::{
    core::Error,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Pipes::DisconnectNamedPipe,
    },
};

#[derive(Debug)]
pub struct NamedPipeServerHandle(HANDLE);

impl Deref for NamedPipeServerHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NamedPipeServerHandle {
    fn drop(&mut self) {
        unsafe {
            _ = DisconnectNamedPipe(self.0);
            _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug)]
pub struct NamedPipeClientHandle(HANDLE);

impl Deref for NamedPipeClientHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NamedPipeClientHandle {
    fn drop(&mut self) {
        unsafe {
            _ = DisconnectNamedPipe(self.0);
        }
    }
}

pub trait FullReader {
    fn read_full(&self) -> Result<Vec<u8>, Error>;
}

pub struct FullReaderIterator<'a>(&'a dyn FullReader);

impl<'a> Iterator for FullReaderIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let Ok(item) = self.0.read_full() else {
            return None;
        };

        Some(item)
    }
}
