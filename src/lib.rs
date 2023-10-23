use std::{
    io::{Read, Write},
    mem,
    os::windows::prelude::{IntoRawHandle, RawHandle},
};
use std::{num::NonZeroU32, os::windows::prelude::AsRawHandle};

use log::debug;
use windows::{
    core::{Error, PCWSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_BUSY,
            ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
            INVALID_HANDLE_VALUE,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
            FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAG_WRITE_THROUGH,
            FILE_READ_ATTRIBUTES, FILE_SHARE_NONE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
            PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, WRITE_DAC, WRITE_OWNER,
        },
        System::{
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PeekNamedPipe,
                SetNamedPipeHandleState, NAMED_PIPE_MODE, PIPE_ACCEPT_REMOTE_CLIENTS, PIPE_NOWAIT,
                PIPE_READMODE_BYTE, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
            },
            SystemServices::ACCESS_SYSTEM_SECURITY,
            IO::OVERLAPPED,
        },
    },
};
use windows_sys::Win32::Storage::FileSystem::ReadFile as ReadFileSys;

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
}

unsafe impl Sync for NamedPipeServerOptions {}
unsafe impl Send for NamedPipeServerOptions {}

impl NamedPipeServerOptions {
    /// Create named pipe server options
    ///
    /// The pipe name must have the following form:
    ///
    /// \\.\pipe\pipename
    ///
    /// The pipename part of the name can include any character other than a backslash, including
    /// numbers and special characters. The entire pipe name string can be up to 256 characters long.
    /// Pipe names are not case sensitive.
    pub fn new(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();

        assert!(
            name.starts_with(r"\\.\pipe\"),
            r"name must start with \\.\pipe\"
        );

        let name_stripped = name.strip_prefix(r"\\.\pipe\").unwrap_or(name);

        assert!(
            !name_stripped.contains('\\'),
            "name must not contain backslash"
        );
        assert!(
            !name_stripped.is_empty() && name_stripped.len() <= 256,
            "name must not be between 1-256"
        );

        let mut name = name.encode_utf16().collect::<Vec<_>>();
        name.push(b'\0' as u16);

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
        self.out_buffer_size = size;
        self
    }

    /// The number of bytes to reserve for the input buffer. For a discussion on sizing named pipe buffers, see
    /// the following Remarks section.
    pub fn in_buffer_size(mut self, size: u32) -> Self {
        self.in_buffer_size = size;
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
            let err = unsafe { GetLastError().expect_err("unreachable") };
            return Err(err);
        }

        Ok(NamedPipeServer {
            options: Some(self.clone()),
            handle,
        })
    }
}

#[derive(Debug, Default)]
pub struct NamedPipeServer {
    options: Option<NamedPipeServerOptions>,
    handle: HANDLE,
}

impl NamedPipeServer {
    /// Create named pipe server from raw handle
    ///
    /// # Safety
    /// handle must be valid named pipe handle, with correct options
    pub unsafe fn from_raw_handle(handle: RawHandle, options: NamedPipeServerOptions) -> Self {
        Self {
            options: Some(options),
            handle: HANDLE(handle as isize),
        }
    }

    /// Sync version
    /// Connect to a single client
    /// See https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    pub fn connect(&self) -> Result<ConnectedClient, Error> {
        unsafe { ConnectNamedPipe(self.handle, None)? };

        Ok(ConnectedClient { server: self })
    }

    /// Async version
    /// Asynchronously connect to a single client
    /// See https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
    pub fn connect_overlapped(
        &self,
        overlapped: *mut OVERLAPPED,
    ) -> Result<ConnectedClient, Error> {
        unsafe { ConnectNamedPipe(self.handle, Some(overlapped))? };

        Ok(ConnectedClient { server: self })
    }

    pub fn disconnect(&self) -> Result<(), Error> {
        unsafe {
            DisconnectNamedPipe(self.handle)?;
        }

        Ok(())
    }

    /// Incoming clients (sync version)
    pub fn incoming(&self) -> IncomingClients {
        IncomingClients { server: self }
    }
}

impl IntoRawHandle for NamedPipeServer {
    fn into_raw_handle(mut self) -> RawHandle {
        let raw_handle = self.handle.0 as *mut _;

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
        self.handle.0 as *mut _
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        unsafe {
            _ = DisconnectNamedPipe(self.handle);
            _ = CloseHandle(self.handle);
        }
    }
}

/// Note that the error variant is NOT an error in the sense of you cannot continue. You should just `continue` on it
/// if there's a real error that cannot be continued on, the iterator will return None instead
#[derive(Debug)]
pub struct IncomingClients<'a> {
    server: &'a NamedPipeServer,
}

impl<'a> Iterator for IncomingClients<'a> {
    type Item = Result<ConnectedClient<'a>, u32>;

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
                return Some(Ok(ConnectedClient {
                    server: self.server,
                }));
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
pub struct ConnectedClient<'server> {
    server: &'server NamedPipeServer,
}

impl<'a> ConnectedClient<'a> {
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
                self.server.handle,
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
    pub fn iter_full(&self) -> FullReaderIterator {
        FullReaderIterator(self)
    }

    /// Read full message/bytes into a vec
    pub fn read_full(&self) -> Result<Vec<u8>, Error> {
        let (available_data, _) = self.available_bytes()?;

        let mut buffer: Vec<u8> = Vec::with_capacity(available_data as usize);

        let mut read_bytes = 0;

        let success = unsafe {
            ReadFileSys(
                self.server.handle.0,
                buffer.as_mut_ptr() as *mut _,
                available_data,
                &mut read_bytes,
                std::ptr::null_mut(),
            ) != 0
        };

        if !success {
            return Err(unsafe { GetLastError().unwrap_err() });
        }

        unsafe {
            buffer.set_len(read_bytes as usize);
        }

        Ok(buffer)
    }

    /// Disconnect the client
    pub fn disconnect(self) -> Result<(), Error> {
        unsafe {
            DisconnectNamedPipe(self.server.handle)?;
        }

        Ok(())
    }

    pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0;

        unsafe {
            WriteFile(self.server.handle, Some(buf), Some(&mut written), None)?;
        }

        Ok(written as usize)
    }

    fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;

        unsafe { ReadFile(self.server.handle, Some(buf), Some(&mut bytes_read), None)? };

        Ok(bytes_read as usize)
    }

    fn flush(&self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(self.server.handle)?;
        }

        Ok(())
    }
}

impl Read for ConnectedClient<'_> {
    /// Read into a buffer, returning how many bytes were read into it
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Self::read(self, buf)
    }
}

impl Write for ConnectedClient<'_> {
    /// Write into a buffer, returning how many bytes were read into it
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Self::write(self, buf)
    }

    /// Flushes the buffers
    /// see: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
    fn flush(&mut self) -> std::io::Result<()> {
        Self::flush(self)
    }
}

pub struct FullReaderIterator<'a>(&'a ConnectedClient<'a>);

impl<'a> Iterator for FullReaderIterator<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let Ok(item) = self.0.read_full() else {
            return None;
        };

        Some(item)
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
    security_attributes: Option<*const SECURITY_ATTRIBUTES>,
}

impl NamedPipeClientOptions {
    /// Create a new named pipe client options
    ///
    /// The pipe name must have the following form:
    ///
    /// \\.\pipe\pipename
    ///
    /// The pipename part of the name can include any character other than a backslash, including
    /// numbers and special characters. The entire pipe name string can be up to 256 characters long.
    /// Pipe names are not case sensitive.
    pub fn new(name: impl AsRef<str>) -> Self {
        let name = name.as_ref();

        assert!(
            name.starts_with(r"\\.\pipe\"),
            r"name must start with \\.\pipe\"
        );

        let name_stripped = name.strip_prefix(r"\\.\pipe\").unwrap_or(name);

        assert!(
            !name_stripped.contains('\\'),
            "name must not contain backslash"
        );
        assert!(
            !name_stripped.is_empty() && name_stripped.len() <= 256,
            "name must not be between 1-256"
        );

        let mut name = name.encode_utf16().collect::<Vec<_>>();
        name.push(b'\0' as u16);

        NamedPipeClientOptions {
            name,
            open_mode: Default::default(),
            // byte mode is default
            pipe_mode: PIPE_READMODE_BYTE.0 | PIPE_WAIT.0,
            collection_data_timeout: Default::default(),
            file_flags: Default::default(),
            security_attributes: Default::default(),
            max_collection_count: Default::default(),
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

    pub fn create(self) -> Result<NamedPipeClient, Error> {
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

        Ok(NamedPipeClient { handle })
    }
}

#[derive(Debug)]
pub struct NamedPipeClient {
    handle: HANDLE,
}

impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;

        unsafe {
            ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None)?;
        }

        Ok(bytes_read as usize)
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut bytes_written = 0;

        unsafe {
            WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None)?;
        }

        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unsafe {
            FlushFileBuffers(self.handle)?;
        }

        Ok(())
    }
}

impl IntoRawHandle for NamedPipeClient {
    fn into_raw_handle(self) -> RawHandle {
        let raw_handle = self.handle.0 as *mut _;

        // don't drop `self`, or it'll close the handle
        // the caller is now responsible for this handle
        mem::forget(self);

        raw_handle
    }
}

impl AsRawHandle for NamedPipeClient {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle.0 as *mut _
    }
}

impl Drop for NamedPipeClient {
    fn drop(&mut self) {
        unsafe {
            _ = CloseHandle(self.handle);
        }
    }
}
