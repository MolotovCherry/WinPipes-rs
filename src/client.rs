use std::{
    io::{Read, Write},
    mem,
    ops::Deref,
    os::windows::prelude::{AsRawHandle, IntoRawHandle, RawHandle},
    sync::Arc,
};

use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_MORE_DATA, GENERIC_READ, GENERIC_WRITE, HANDLE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_FLAG_WRITE_THROUGH, FILE_READ_ATTRIBUTES, FILE_SHARE_NONE, FILE_WRITE_ATTRIBUTES,
            OPEN_EXISTING,
        },
        System::Pipes::{
            PeekNamedPipe, SetNamedPipeHandleState, NAMED_PIPE_MODE, PIPE_NOWAIT,
            PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE, PIPE_WAIT,
        },
    },
};
use windows_sys::Win32::Storage::FileSystem::ReadFile as ReadFileSys;

use crate::{FullReader, FullReaderIterator};

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
            _ = CloseHandle(self.0);
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamedPipeClientOptions {
    name: Vec<u16>,
    open_mode: u32,
    pipe_mode: u32,
    collection_data_timeout: Option<u32>,
    file_flags: u32,
    max_collection_count: Option<u32>,
    read_buffer_size: u32,
    security_attributes: Option<*const SECURITY_ATTRIBUTES>,
}

unsafe impl Send for NamedPipeClientOptions {}
unsafe impl Sync for NamedPipeClientOptions {}

impl NamedPipeClientOptions {
    /// Create a new named pipe client options
    ///
    /// The pipename part of the name can include any character other than a backslash, including
    /// numbers and special characters. The entire pipe name string can be up to 256 characters long.
    /// Pipe names are not case sensitive.
    pub fn new(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();

        assert!(
            !name.starts_with(r"\\.\pipe\"),
            r"name must not start with \\.\pipe\"
        );

        assert!(!name.contains('\\'), "name must not contain backslash");
        assert!(
            !name.is_empty() && name.len() <= 256,
            "name must not be between 1-256"
        );

        let mut name = format!(r"\\.\pipe\{name}")
            .encode_utf16()
            .collect::<Vec<_>>();
        name.push(0);

        NamedPipeClientOptions {
            name,
            open_mode: Default::default(),
            // byte mode is default
            pipe_mode: PIPE_READMODE_BYTE.0 | PIPE_WAIT.0,
            collection_data_timeout: Default::default(),
            file_flags: Default::default(),
            security_attributes: Default::default(),
            max_collection_count: Default::default(),
            read_buffer_size: 1024,
        }
    }

    /// The pipe is bi-directional; both server and client processes can read from and write
    /// to the pipe. This mode gives the server the equivalent of GENERIC_READ and GENERIC_WRITE
    /// access to the pipe. The client can specify GENERIC_READ or GENERIC_WRITE, or both, when
    /// it connects to the pipe using the CreateFile function.
    pub fn access_duplex(mut self) -> Self {
        self.open_mode = GENERIC_READ.0 | GENERIC_WRITE.0;
        self
    }

    /// The flow of data in the pipe goes from client to server only. This mode gives the server
    /// the equivalent of GENERIC_READ access to the pipe. The client must specify GENERIC_WRITE
    /// access when connecting to the pipe. If the client must read pipe settings by calling the
    /// GetNamedPipeInfo or GetNamedPipeHandleState functions, the client must specify GENERIC_WRITE
    /// and FILE_READ_ATTRIBUTES access when connecting to the pipe.
    pub fn access_outbound(mut self) -> Self {
        self.open_mode = GENERIC_WRITE.0 | FILE_READ_ATTRIBUTES.0;
        self
    }

    /// The flow of data in the pipe goes from server to client only. This mode gives the server
    /// the equivalent of GENERIC_WRITE access to the pipe. The client must specify GENERIC_READ
    /// access when connecting to the pipe. If the client must change pipe settings by calling
    /// the SetNamedPipeHandleState function, the client must specify GENERIC_READ and
    /// FILE_WRITE_ATTRIBUTES access when connecting to the pipe.
    pub fn access_inbound(mut self) -> Self {
        self.open_mode = GENERIC_READ.0 | FILE_WRITE_ATTRIBUTES.0;
        self
    }

    /// Blocking mode is enabled. When the pipe handle is specified in the ReadFile, WriteFile, or
    /// ConnectNamedPipe function, the operations are not completed until there is data to read, all data is
    /// written, or a client is connected. Use of this mode can mean waiting indefinitely in some situations
    /// for a client process to perform an action.
    pub fn wait(mut self) -> Self {
        self.pipe_mode |= PIPE_WAIT.0;
        self
    }

    /// Nonblocking mode is enabled. In this mode, ReadFile, WriteFile, and ConnectNamedPipe always return immediately.
    ///
    /// Note that nonblocking mode is supported for compatibility with Microsoft LAN Manager version 2.0 and should
    /// not be used to achieve asynchronous I/O with named pipes. For more information on asynchronous pipe I/O,
    /// see Synchronous and Overlapped Input and Output.
    pub fn nowait(mut self) -> Self {
        self.pipe_mode |= PIPE_NOWAIT.0;
        self
    }

    /// Data is read from the pipe as a stream of bytes. This mode can be used with either PIPE_TYPE_MESSAGE
    /// or PIPE_TYPE_BYTE.
    pub fn mode_byte(mut self) -> Self {
        self.pipe_mode |= PIPE_READMODE_BYTE.0;
        self
    }

    /// Data is read from the pipe as a stream of messages. This mode can be only used if PIPE_TYPE_MESSAGE is
    /// also specified.
    pub fn mode_message(mut self) -> Self {
        self.pipe_mode |= PIPE_READMODE_MESSAGE.0;
        self
    }

    /// The maximum time, in milliseconds, that can pass before a remote named pipe transfers information over
    /// the network. This parameter must be NULL if the specified pipe handle is to the server end of a named pipe
    /// or if client and server processes are on the same computer. This parameter is ignored if the client process
    /// specified the FILE_FLAG_WRITE_THROUGH flag in the CreateFile function when the handle was created. This
    /// parameter can be NULL if the collection count is not being set.
    pub fn collection_data_timeout(mut self, timeout: u32) -> Self {
        self.collection_data_timeout = Some(timeout);
        self
    }

    /// Write-through mode is enabled. This mode affects only write operations on byte-type pipes
    /// and, then, only when the client and server processes are on different computers. If this mode
    /// is enabled, functions writing to a named pipe do not return until the data written is
    /// transmitted across the network and is in the pipe's buffer on the remote computer. If this
    /// mode is not enabled, the system enhances the efficiency of network operations by buffering
    /// data until a minimum number of bytes accumulate or until a maximum time elapses.
    pub fn write_through(mut self) -> Self {
        self.file_flags |= FILE_FLAG_WRITE_THROUGH.0;
        self
    }

    /// The maximum number of bytes collected on the client computer before transmission to the server. This
    /// parameter must be NULL if the specified pipe handle is to the server end of a named pipe or if client
    /// and server processes are on the same machine. This parameter is ignored if the client process specifies
    /// the FILE_FLAG_WRITE_THROUGH flag in the CreateFile function when the handle was created. This parameter
    /// can be NULL if the collection count is not being set.
    pub fn max_count(mut self, max: u32) -> Self {
        self.max_collection_count = Some(max);
        self
    }

    pub fn read_buffer_size(mut self, size: u32) -> Self {
        assert!(size > 0, "size must be > 0");
        self.read_buffer_size = size;
        self
    }

    pub fn create(self) -> Result<(NamedPipeClientReader, NamedPipeClientWriter), Error> {
        let handle = unsafe {
            CreateFileW(
                PCWSTR(self.name.as_ptr()),
                self.open_mode,
                FILE_SHARE_NONE,
                self.security_attributes,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(self.file_flags),
                None,
            )?
        };

        unsafe {
            SetNamedPipeHandleState(
                handle,
                Some(&NAMED_PIPE_MODE(self.pipe_mode)),
                self.max_collection_count.map(|m| &m as _),
                self.collection_data_timeout.map(|t| t as _),
            )?;
        }

        let handle = Arc::new(NamedPipeClientHandle(handle));

        Ok((
            NamedPipeClientReader {
                options: self.clone(),
                handle: handle.clone(),
            },
            NamedPipeClientWriter {
                handle: handle.clone(),
            },
        ))
    }
}

#[derive(Debug)]
pub struct NamedPipeClientReader {
    options: NamedPipeClientOptions,
    handle: Arc<NamedPipeClientHandle>,
}

impl NamedPipeClientReader {
    /// How many bytes are available to be read
    ///
    /// Returns (A, L)
    ///
    /// Where A: how many total bytes are available
    /// where L: how many bytes left of this message
    pub fn available_bytes(&self) -> Result<(u32, u32), Error> {
        let mut available = 0;
        let mut left_message = 0;

        unsafe {
            PeekNamedPipe(
                self.handle.0,
                None,
                0,
                None,
                Some(&mut available),
                Some(&mut left_message),
            )?;
        }

        Ok((available, left_message))
    }

    /// Iterator over full messages/bytes into a vec
    pub fn iter_read_full(&self) -> FullReaderIterator {
        FullReaderIterator(self)
    }

    /// Read full message/bytes into a vec
    pub fn read_full(&self) -> Result<Vec<u8>, Error> {
        let buffer_size = self.options.read_buffer_size as usize;

        let mut buffer = Vec::new();
        let mut total_read_bytes = 0;

        loop {
            let old_buffer_size = buffer.len();
            let new_buffer_size = old_buffer_size + buffer_size;
            buffer.resize(new_buffer_size, 0);

            let buffer_end = &mut buffer[old_buffer_size..];
            let mut read_bytes = 0;
            let result = unsafe {
                ReadFileSys(
                    self.handle.0 .0,
                    buffer_end.as_mut_ptr(),
                    buffer_end.len() as u32,
                    &mut read_bytes,
                    std::ptr::null_mut(),
                )
            };

            total_read_bytes += read_bytes as usize;

            if result != 0 {
                // Read was successful
                buffer.resize(total_read_bytes, 0);
                return Ok(buffer);
            }

            let err = unsafe { GetLastError() };
            if err.is_err() && err != ERROR_MORE_DATA {
                // An error occurred during reading
                return Err(err.into());
            }

            // Read succeeded, but this message has more data
        }
    }
}

impl FullReader for NamedPipeClientReader {
    fn read_full(&self) -> Result<Vec<u8>, Error> {
        self.read_full()
    }
}

impl Read for NamedPipeClientReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;

        unsafe {
            ReadFile(**self.handle, Some(buf), Some(&mut bytes_read), None)?;
        }

        Ok(bytes_read as usize)
    }
}

/// This is only okay to call if the NamedPipeClientWriter has already been dropped!
impl IntoRawHandle for NamedPipeClientReader {
    fn into_raw_handle(self) -> RawHandle {
        let handle = Arc::into_inner(self.handle)
            .expect("can't consume handle because NamedPipeClientWriter is alive");

        let raw_handle = handle.0;

        // don't drop, or it'll close the handle
        // the caller is now responsible for this handle
        mem::forget(handle);

        raw_handle.0 as *mut _
    }
}

impl AsRawHandle for NamedPipeClientReader {
    fn as_raw_handle(&self) -> RawHandle {
        (**self.handle).0 as *mut _
    }
}

#[derive(Debug)]
pub struct NamedPipeClientWriter {
    handle: Arc<NamedPipeClientHandle>,
}

impl Write for NamedPipeClientWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0;

        unsafe {
            WriteFile(**self.handle, Some(buf), Some(&mut bytes_written), None)?;
        }

        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(**self.handle)?;
        }

        Ok(())
    }
}

/// This is only okay to call if the NamedPipeClientReader has already been dropped!
impl IntoRawHandle for NamedPipeClientWriter {
    fn into_raw_handle(self) -> RawHandle {
        let handle = Arc::into_inner(self.handle)
            .expect("can't consume handle because NamedPipeClientReader is alive");

        let raw_handle = handle.0;

        // don't drop, or it'll close the handle
        // the caller is now responsible for this handle
        mem::forget(handle);

        raw_handle.0 as *mut _
    }
}

impl AsRawHandle for NamedPipeClientWriter {
    fn as_raw_handle(&self) -> RawHandle {
        (**self.handle).0 as *mut _
    }
}
