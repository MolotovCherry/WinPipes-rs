use std::{
    io::{Read, Write},
    mem,
    ops::Deref,
    os::windows::prelude::{IntoRawHandle, RawHandle},
    sync::Arc,
};
use std::{num::NonZeroU32, os::windows::prelude::AsRawHandle};

use log::debug;
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA,
            ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Security::{RevertToSelf, SECURITY_ATTRIBUTES},
        Storage::FileSystem::{
            FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAG_WRITE_THROUGH,
            PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
                ImpersonateNamedPipeClient, PeekNamedPipe, NAMED_PIPE_MODE,
                PIPE_ACCEPT_REMOTE_CLIENTS, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE,
                PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
            },
            SystemServices::ACCESS_SYSTEM_SECURITY,
            IO::OVERLAPPED,
        },
    },
};
use windows_sys::Win32::Storage::FileSystem::ReadFile as ReadFileSys;

use crate::{FullReader, FullReaderIterator};

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

#[derive(Debug, Clone)]
pub struct NamedPipeServerClientHandle(HANDLE);

impl Deref for NamedPipeServerClientHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NamedPipeServerClientHandle {
    fn drop(&mut self) {
        unsafe {
            _ = DisconnectNamedPipe(self.0);
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum PipeReadMode {
    ReadByte,
    ReadMsg,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum PipeWriteMode {
    WriteByte,
    WriteMsg,
}

#[derive(Debug, Clone)]
pub struct NamedPipeServerOptions {
    name: Vec<u16>,
    open_mode: u32,
    pipe_mode: u32,
    max_instances: NonZeroU32,
    out_buffer_size: u32,
    in_buffer_size: u32,
    default_timeout: u32,
    read_mode: PipeReadMode,
    write_mode: PipeWriteMode,
    security_attributes: Option<*const SECURITY_ATTRIBUTES>,
    impersonate: bool,
}

unsafe impl Sync for NamedPipeServerOptions {}
unsafe impl Send for NamedPipeServerOptions {}

impl NamedPipeServerOptions {
    /// Create named pipe server options
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

        NamedPipeServerOptions {
            name,
            open_mode: Default::default(),
            // byte mode is default
            // despite the normal default, remote clients are rejected by default for security reasons
            pipe_mode: PIPE_TYPE_BYTE.0
                | PIPE_READMODE_BYTE.0
                | PIPE_WAIT.0
                | PIPE_REJECT_REMOTE_CLIENTS.0,
            max_instances: NonZeroU32::new(1).unwrap(),
            out_buffer_size: Default::default(),
            in_buffer_size: Default::default(),
            default_timeout: Default::default(),
            security_attributes: Default::default(),
            read_mode: PipeReadMode::ReadByte,
            write_mode: PipeWriteMode::WriteByte,
            impersonate: false,
        }
    }

    /// The pipe is bi-directional; both server and client processes can read from and write
    /// to the pipe. This mode gives the server the equivalent of GENERIC_READ and GENERIC_WRITE
    /// access to the pipe. The client can specify GENERIC_READ or GENERIC_WRITE, or both, when
    /// it connects to the pipe using the CreateFile function.
    pub fn access_duplex(mut self) -> Self {
        self.open_mode |= PIPE_ACCESS_DUPLEX.0;
        self
    }

    /// The flow of data in the pipe goes from client to server only. This mode gives the server
    /// the equivalent of GENERIC_READ access to the pipe. The client must specify GENERIC_WRITE
    /// access when connecting to the pipe. If the client must read pipe settings by calling the
    /// GetNamedPipeInfo or GetNamedPipeHandleState functions, the client must specify GENERIC_WRITE
    /// and FILE_READ_ATTRIBUTES access when connecting to the pipe.
    pub fn access_inbound(mut self) -> Self {
        self.open_mode |= PIPE_ACCESS_INBOUND.0;
        self
    }

    /// The flow of data in the pipe goes from server to client only. This mode gives the server
    /// the equivalent of GENERIC_WRITE access to the pipe. The client must specify GENERIC_READ
    /// access when connecting to the pipe. If the client must change pipe settings by calling
    /// the SetNamedPipeHandleState function, the client must specify GENERIC_READ and
    /// FILE_WRITE_ATTRIBUTES access when connecting to the pipe.
    pub fn access_outbound(mut self) -> Self {
        self.open_mode |= PIPE_ACCESS_OUTBOUND.0;
        self
    }

    /// If you attempt to create multiple instances of a pipe with this flag, creation of the
    /// first instance succeeds, but creation of the next instance fails with ERROR_ACCESS_DENIED.
    pub fn first_pipe_instance(mut self) -> Self {
        self.open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE.0;
        self
    }

    /// Write-through mode is enabled. This mode affects only write operations on byte-type pipes
    /// and, then, only when the client and server processes are on different computers. If this mode
    /// is enabled, functions writing to a named pipe do not return until the data written is
    /// transmitted across the network and is in the pipe's buffer on the remote computer. If this
    /// mode is not enabled, the system enhances the efficiency of network operations by buffering
    /// data until a minimum number of bytes accumulate or until a maximum time elapses.
    pub fn write_through(mut self) -> Self {
        self.open_mode |= FILE_FLAG_WRITE_THROUGH.0;
        self
    }

    /// Overlapped mode is enabled. If this mode is enabled, functions performing read, write,
    /// and connect operations that may take a significant time to be completed can return
    /// immediately. This mode enables the thread that started the operation to perform other
    /// operations while the time-consuming operation executes in the background. For example,
    /// in overlapped mode, a thread can handle simultaneous input and output (I/O) operations
    /// on multiple instances of a pipe or perform simultaneous read and write operations on the
    /// same pipe handle. If overlapped mode is not enabled, functions performing read, write,
    /// and connect operations on the pipe handle do not return until the operation is finished.
    /// The ReadFileEx and WriteFileEx functions can only be used with a pipe handle in overlapped
    /// mode. The ReadFile, WriteFile, ConnectNamedPipe, and TransactNamedPipe functions can
    /// execute either synchronously or as overlapped operations.
    pub fn overlapped(mut self) -> Self {
        self.open_mode |= FILE_FLAG_OVERLAPPED.0;
        self
    }

    /// The caller will have write access to the named pipe's discretionary access control list (ACL).
    pub fn write_dac(mut self) -> Self {
        self.open_mode |= WRITE_DAC.0;
        self
    }

    /// The caller will have write access to the named pipe's owner.
    pub fn write_owner(mut self) -> Self {
        self.open_mode |= WRITE_OWNER.0;
        self
    }

    /// The caller will have write access to the named pipe's SACL. For more information, see Access-Control
    /// Lists (ACLs) and SACL Access Right.
    pub fn access_system_security(mut self) -> Self {
        self.open_mode |= ACCESS_SYSTEM_SECURITY;
        self
    }

    /// Data is written to the pipe as a stream of bytes. This mode cannot be used with PIPE_READMODE_MESSAGE.
    /// The pipe does not distinguish bytes written during different write operations.
    pub fn write_byte(mut self) -> Self {
        self.write_mode = PipeWriteMode::WriteByte;
        self.pipe_mode |= PIPE_TYPE_BYTE.0;
        self
    }

    /// Data is written to the pipe as a stream of messages. The pipe treats the bytes written during each
    /// write operation as a message unit. The GetLastError function returns ERROR_MORE_DATA when a message
    /// is not read completely. This mode can be used with either PIPE_READMODE_MESSAGE or PIPE_READMODE_BYTE.
    pub fn write_message(mut self) -> Self {
        self.write_mode = PipeWriteMode::WriteMsg;
        self.pipe_mode |= PIPE_TYPE_MESSAGE.0;
        self
    }

    /// Data is read from the pipe as a stream of bytes. This mode can be used with either PIPE_TYPE_MESSAGE
    /// or PIPE_TYPE_BYTE.
    pub fn read_byte(mut self) -> Self {
        self.read_mode = PipeReadMode::ReadByte;
        self.pipe_mode |= PIPE_READMODE_BYTE.0;
        self
    }

    /// Data is read from the pipe as a stream of messages. This mode can be only used if PIPE_TYPE_MESSAGE is
    /// also specified.
    pub fn read_message(mut self) -> Self {
        self.read_mode = PipeReadMode::ReadMsg;
        self.pipe_mode |= PIPE_READMODE_MESSAGE.0;
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

    /// Connections from remote clients can be accepted and checked against the security descriptor for the pipe.
    pub fn accept_remote(mut self) -> Self {
        self.pipe_mode |= PIPE_ACCEPT_REMOTE_CLIENTS.0;
        self
    }

    /// Connections from remote clients are automatically rejected.
    pub fn reject_remote(mut self) -> Self {
        self.pipe_mode |= PIPE_REJECT_REMOTE_CLIENTS.0;
        self
    }

    /// The maximum number of instances that can be created for this pipe. The first instance of the pipe can specify
    /// this value; the same number must be specified for other instances of the pipe. Acceptable values are in the
    /// range 1 through 254
    pub fn max_instances(mut self, instances: u32) -> Self {
        assert!(
            (1..=254).contains(&instances),
            "number of max instances must be 1-254; if you wanted PIPE_UNLIMITED_INSTANCES, use unlimited_instances()"
        );

        self.max_instances = NonZeroU32::new(instances).unwrap();
        self
    }

    /// The number of pipe instances that can be created is limited only by the availability of system resources.
    /// If nMaxInstances is greater than PIPE_UNLIMITED_INSTANCES, the return value is INVALID_HANDLE_VALUE and
    /// GetLastError returns ERROR_INVALID_PARAMETER.
    pub fn unlimited_instances(mut self) -> Self {
        self.max_instances = NonZeroU32::new(255).unwrap();
        self
    }

    /// The number of bytes to reserve for the output buffer. For a discussion on sizing named pipe buffers, see
    /// the following Remarks section.
    pub fn out_buffer_size(mut self, size: u32) -> Self {
        assert!(size > 0, "size must be > 0");
        self.out_buffer_size = size;
        self
    }

    /// The number of bytes to reserve for the input buffer. For a discussion on sizing named pipe buffers, see
    /// the following Remarks section.
    pub fn in_buffer_size(mut self, size: u32) -> Self {
        assert!(size > 0, "size must be > 0");
        self.in_buffer_size = size;
        self
    }

    /// The ImpersonateNamedPipeClient function impersonates a named-pipe client application.
    pub fn impersonate(mut self) -> Self {
        self.impersonate = true;
        self
    }

    /// The default time-out value, in milliseconds, if the WaitNamedPipe function specifies NMPWAIT_USE_DEFAULT_WAIT.
    /// Each instance of a named pipe must specify the same value.
    ///
    /// A value of zero will result in a default time-out of 50 milliseconds.
    pub fn default_timeout(mut self, timeout: u32) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new
    /// named pipe and determines whether child processes can inherit the returned handle. If
    /// lpSecurityAttributes is NULL, the named pipe gets a default security descriptor and the handle
    /// cannot be inherited. The ACLs in the default security descriptor for a named pipe grant full
    /// control to the LocalSystem account, administrators, and the creator owner. They also grant
    /// read access to members of the Everyone group and the anonymous account.
    pub fn security_attributes(mut self, security_attributes: *const SECURITY_ATTRIBUTES) -> Self {
        self.security_attributes = Some(security_attributes);
        self
    }

    /// Create the pipeserver
    pub fn create(self) -> Result<NamedPipeServer, Error> {
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(self.name.as_ptr()),
                FILE_FLAGS_AND_ATTRIBUTES(self.open_mode),
                NAMED_PIPE_MODE(self.pipe_mode),
                self.max_instances.get(),
                self.out_buffer_size,
                self.in_buffer_size,
                self.default_timeout,
                self.security_attributes,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            return Err(err.into());
        }

        if self.impersonate {
            unsafe {
                ImpersonateNamedPipeClient(handle)?;
            }
        }

        Ok(NamedPipeServer {
            options: Some(self.clone()),
            handle: NamedPipeServerClientHandle(handle),
        })
    }
}

#[derive(Debug, Clone)]
pub struct NamedPipeServer {
    options: Option<NamedPipeServerOptions>,
    handle: NamedPipeServerClientHandle,
}

impl NamedPipeServer {
    /// Create named pipe server from raw handle
    ///
    /// # Safety
    /// handle must be valid named pipe handle, with correct options
    pub unsafe fn from_raw_handle(handle: RawHandle, options: NamedPipeServerOptions) -> Self {
        Self {
            options: Some(options),
            handle: NamedPipeServerClientHandle(HANDLE(handle as isize)),
        }
    }

    /// Sync version
    /// Connect to a single client
    /// See https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    pub fn connect(&self) -> Result<(ConnectedClientReader, ConnectedClientWriter), Error> {
        unsafe { ConnectNamedPipe(self.handle.0, None)? };

        let dropper = Arc::new(NamedPipeServerClientHandle(self.handle.0));

        Ok((
            ConnectedClientReader {
                server: Self {
                    options: self.options.clone(),
                    handle: self.handle.clone(),
                },
                dropper: dropper.clone(),
            },
            ConnectedClientWriter {
                server: Self {
                    options: self.options.clone(),
                    handle: self.handle.clone(),
                },
                dropper,
            },
        ))
    }

    /// The RevertToSelf function terminates the impersonation of a client application.
    pub fn revert_to_self(&self) -> Result<(), Error> {
        unsafe { RevertToSelf() }
    }

    /// Async version
    /// Asynchronously connect to a single client
    /// See https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    pub fn connect_overlapped(
        &self,
        overlapped: *mut OVERLAPPED,
    ) -> Result<(ConnectedClientReader, ConnectedClientWriter), Error> {
        unsafe { ConnectNamedPipe(self.handle.0, Some(overlapped))? };

        let dropper = Arc::new(NamedPipeServerClientHandle(self.handle.0));

        Ok((
            ConnectedClientReader {
                server: Self {
                    options: self.options.clone(),
                    handle: self.handle.clone(),
                },
                dropper: dropper.clone(),
            },
            ConnectedClientWriter {
                server: Self {
                    options: self.options.clone(),
                    handle: self.handle.clone(),
                },
                dropper,
            },
        ))
    }

    /// Disconnect the client. Will fail if pipe is in use in other areas (e.g. iterators)
    /// Everything that could be using it must be dropped for this to succeed
    pub fn disconnect(&self) -> Result<(), Error> {
        unsafe {
            DisconnectNamedPipe(self.handle.0)?;
        }

        Ok(())
    }

    pub fn incoming(&self) -> ClientIterator {
        self.into_iter()
    }
}

impl IntoRawHandle for NamedPipeServer {
    fn into_raw_handle(mut self) -> RawHandle {
        let raw_handle = self.handle.0 .0 as *mut _;

        // drop the options since we don't need it
        mem::drop(self.options.take());

        // don't drop `self`, or it'll close the handle
        // the caller is now responsible for this handle
        mem::forget(self);

        raw_handle
    }
}

impl AsRawHandle for NamedPipeServer {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.0 .0 as *mut _
    }
}

impl IntoIterator for &NamedPipeServer {
    type Item = Result<(ConnectedClientReader, ConnectedClientWriter), u32>;

    type IntoIter = ClientIterator;

    fn into_iter(self) -> Self::IntoIter {
        ClientIterator {
            server: NamedPipeServer {
                options: self.options.clone(),
                handle: self.handle.clone(),
            },
        }
    }
}

#[derive(Debug)]
pub struct ClientIterator {
    server: NamedPipeServer,
}

/// Note that the error variant is NOT an error in the sense of you cannot continue. You should just `continue` on it
/// if there's a real error that cannot be continued on, the iterator will return None instead
impl Iterator for ClientIterator {
    type Item = Result<(ConnectedClientReader, ConnectedClientWriter), u32>;

    fn next(&mut self) -> Option<Self::Item> {
        let connect = self.server.connect();
        let Ok(client) = connect else {
            let e = connect.unwrap_err();
            let code = (e.code().0 & 0x0000FFFF) as u32;

            let is_success = code == ERROR_PIPE_CONNECTED.0;

            if !is_success {
                // these error codes are not errors, we can safely continue
                let ok_errors = [
                    // No process is on the other end of the pipe.
                    ERROR_PIPE_NOT_CONNECTED.0,
                    // The pipe has been ended.
                    ERROR_BROKEN_PIPE.0,
                    // All pipe instances are busy.
                    ERROR_PIPE_BUSY.0,
                    // The pipe is being closed.
                    ERROR_NO_DATA.0,
                ];

                match code {
                    // the error isn't an error per se, but we should continue and try again
                    _ if ok_errors.contains(&code) => {
                        _ = self.server.disconnect();
                        return Some(Err(code));
                    }
                    // some other internal error we cannot continue on
                    _ => {
                        debug!("IncomingClients::next() returned: {e}");
                        _ = self.server.disconnect();
                        return None;
                    }
                }
            } else {
                let dropper = Arc::new(NamedPipeServerClientHandle(self.server.handle.0));

                return Some(Ok((
                    ConnectedClientReader {
                        server: NamedPipeServer {
                            options: self.server.options.clone(),
                            handle: self.server.handle.clone(),
                        },
                        dropper: dropper.clone(),
                    },
                    ConnectedClientWriter {
                        server: NamedPipeServer {
                            options: self.server.options.clone(),
                            handle: self.server.handle.clone(),
                        },
                        dropper,
                    },
                )));
            }
        };

        Some(Ok(client))
    }
}

/// Represents a connected client
///
/// Why borrow handle when it's Copy?
/// That's because it only lives as long as the server lives
/// So this is for type checking purposes
#[derive(Debug)]
pub struct ConnectedClientReader {
    server: NamedPipeServer,
    #[allow(unused)]
    dropper: Arc<NamedPipeServerClientHandle>,
}

impl ConnectedClientReader {
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
                self.server.handle.0,
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
        let buffer_size = self
            .server
            .options
            .as_ref()
            .map(|o| o.out_buffer_size)
            .unwrap_or(1024) as usize;

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
                    self.server.handle.0 .0,
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

impl FullReader for ConnectedClientReader {
    fn read_full(&self) -> Result<Vec<u8>, Error> {
        self.read_full()
    }
}

impl Read for ConnectedClientReader {
    /// Read into a buffer, returning how many bytes were read into it
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;

        unsafe { ReadFile(self.server.handle.0, Some(buf), Some(&mut bytes_read), None)? };

        Ok(bytes_read as usize)
    }
}

/// Represents the write portion of a connected client
///
/// Why borrow handle when it's Copy?
/// That's because it only lives as long as the server lives
/// So this is for type checking purposes
#[derive(Debug)]
pub struct ConnectedClientWriter {
    server: NamedPipeServer,
    #[allow(unused)]
    dropper: Arc<NamedPipeServerClientHandle>,
}

impl Write for ConnectedClientWriter {
    /// Write into a buffer, returning how many bytes were read into it
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;

        unsafe {
            WriteFile(self.server.handle.0, Some(buf), Some(&mut written), None)?;
        }

        Ok(written as usize)
    }

    /// Flushes the buffers
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(self.server.handle.0)?;
        }

        Ok(())
    }
}
