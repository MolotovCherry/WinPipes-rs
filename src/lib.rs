mod client;
mod server;

pub use client::*;
pub use server::*;
use windows::core::Error;

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
