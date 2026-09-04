//! Capability-anchored, bounded local file operations.

use std::{
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    path::{Component, Path},
};

use cap_fs_ext::{
    FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _,
};
use cap_std::{
    ambient_authority,
    fs::{Dir, Metadata, OpenOptions},
};
use thiserror::Error;

const READ_CHUNK: usize = 64 * 1024;
const REPLACE_LOCK_NAME: &str = ".kirje-local-io.lock";

/// Errors produced at Kirje's local file boundary.
#[derive(Debug, Error)]
pub enum BoundaryError {
    /// The requested path cannot name one unambiguous final component.
    #[error("path must name one unambiguous file")]
    InvalidPath,
    /// The final component is a symbolic link or equivalent indirection.
    #[error("linked files are not accepted")]
    LinkRejected,
    /// The opened object is not a regular file.
    #[error("path must identify a regular file")]
    NotRegularFile,
    /// The opened object does not match the caller's compare-and-swap token.
    #[error("file changed before replacement")]
    IdentityMismatch,
    /// Input exceeded its declared byte budget or memory could not be reserved.
    #[error("input exceeds the {limit}-byte limit")]
    ResourceLimit {
        /// Maximum accepted byte count.
        limit: usize,
    },
    /// The operating system rejected the requested filesystem operation.
    #[error("local file operation failed")]
    Io(#[source] io::Error),
}

impl From<io::Error> for BoundaryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Stable identity read from an already-open file handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileObjectIdentity {
    device: u64,
    inode: u64,
}

impl FileObjectIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    /// Return canonical numeric material for authority-context binding.
    #[must_use]
    pub const fn canonical_material(self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

/// Stable identity read from an already-open parent directory handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    /// Return canonical numeric material for authority-context binding.
    #[must_use]
    pub const fn canonical_material(self) -> (u64, u64) {
        (self.device, self.inode)
    }
}

/// An opened parent directory plus its validated final path component.
pub struct OpenedParent {
    dir: Dir,
    final_component: OsString,
    identity: DirectoryIdentity,
}

impl OpenedParent {
    /// Identity derived from the open directory handle.
    #[must_use]
    pub const fn identity(&self) -> DirectoryIdentity {
        self.identity
    }

    /// The single final component relative to the held directory handle.
    #[must_use]
    pub fn final_component(&self) -> &OsStr {
        &self.final_component
    }
}

/// A regular file validated from metadata on the open handle.
pub struct OpenedRegularFile {
    file: cap_std::fs::File,
    metadata: Metadata,
    object: FileObjectIdentity,
}

impl OpenedRegularFile {
    /// Length reported by the open handle.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.metadata.len()
    }

    /// Whether the opened file has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Identity derived from the open file handle.
    #[must_use]
    pub const fn identity(&self) -> FileObjectIdentity {
        self.object
    }
}

/// Compare-and-swap condition for a private file replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaceExpectation {
    /// The destination must not exist.
    Missing,
    /// The destination must still identify this opened object.
    Matches(FileObjectIdentity),
    /// Replace any regular destination, while still rejecting links.
    Any,
}

/// Open a path's parent once and retain a capability to that exact directory.
///
/// # Errors
///
/// Returns [`BoundaryError::InvalidPath`] for ambiguous final components, or a
/// stable I/O boundary error if the parent cannot be opened.
pub fn open_parent(path: &Path) -> Result<OpenedParent, BoundaryError> {
    let final_component = path.file_name().ok_or(BoundaryError::InvalidPath)?;
    validate_final_component(final_component)?;

    let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
    let parent_path = if parent_path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent_path
    };
    let dir = Dir::open_ambient_dir(parent_path, ambient_authority()).map_err(BoundaryError::Io)?;
    let metadata = dir.dir_metadata().map_err(BoundaryError::Io)?;
    let identity = DirectoryIdentity::from_metadata(&metadata);
    Ok(OpenedParent {
        dir,
        final_component: final_component.to_owned(),
        identity,
    })
}

/// Open the final component without following links and require a regular file.
///
/// # Errors
///
/// Rejects links and non-regular objects before returning an open handle.
pub fn open_existing_regular(parent: &OpenedParent) -> Result<OpenedRegularFile, BoundaryError> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No).nonblock(true);
    let file = parent
        .dir
        .open_with(&parent.final_component, &options)
        .map_err(|error| map_open_error(&parent.dir, &parent.final_component, error))?;
    opened_regular(file)
}

/// Read one opened regular file without ever requesting more than `limit + 1` bytes.
///
/// # Errors
///
/// Returns [`BoundaryError::ResourceLimit`] when the file exceeds `limit`.
pub fn read_bounded(
    opened: &mut OpenedRegularFile,
    limit: usize,
) -> Result<Vec<u8>, BoundaryError> {
    if opened.metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) {
        return Err(BoundaryError::ResourceLimit { limit });
    }
    read_stream_bounded(&mut opened.file, limit)
}

/// Read an arbitrary stream using a fixed scratch buffer and a strict byte budget.
///
/// # Errors
///
/// Returns [`BoundaryError::ResourceLimit`] when more than `limit` bytes arrive.
pub fn read_stream_bounded<R: Read>(
    reader: &mut R,
    limit: usize,
) -> Result<Vec<u8>, BoundaryError> {
    let probe_limit = limit.saturating_add(1);
    let mut output = Vec::new();
    output
        .try_reserve(limit.min(READ_CHUNK))
        .map_err(|_| BoundaryError::ResourceLimit { limit })?;
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(READ_CHUNK)
        .map_err(|_| BoundaryError::ResourceLimit { limit })?;
    scratch.resize(READ_CHUNK, 0);

    loop {
        let remaining = probe_limit.saturating_sub(output.len());
        if remaining == 0 {
            return Err(BoundaryError::ResourceLimit { limit });
        }
        let requested = remaining.min(scratch.len());
        match reader.read(&mut scratch[..requested]) {
            Ok(0) => return Ok(output),
            Ok(read) => {
                output
                    .try_reserve(read)
                    .map_err(|_| BoundaryError::ResourceLimit { limit })?;
                output.extend_from_slice(&scratch[..read]);
                if output.len() > limit {
                    return Err(BoundaryError::ResourceLimit { limit });
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(BoundaryError::Io(error)),
        }
    }
}

/// Atomically replace a private regular file relative to one opened parent.
///
/// The temporary file is mode `0600` on Unix and synchronized before success is
/// returned. The parent directory is also synchronized on Unix. Kirje writers
/// sharing that parent are serialized through a private advisory lock before
/// the compare-and-swap identity is checked.
///
/// # Errors
///
/// Rejects linked destinations and stale compare-and-swap identities.
pub fn replace_private(
    parent: &OpenedParent,
    expected: ReplaceExpectation,
    bytes: &[u8],
) -> Result<FileObjectIdentity, BoundaryError> {
    replace_private_inner(parent, expected, bytes, || {})
}

fn replace_private_inner(
    parent: &OpenedParent,
    expected: ReplaceExpectation,
    bytes: &[u8],
    before_commit: impl FnOnce(),
) -> Result<FileObjectIdentity, BoundaryError> {
    let _replace_lock = acquire_replace_lock(parent)?;
    verify_expectation(parent, expected)?;
    let temporary = create_private_temporary(parent)?;
    let temporary_name = temporary.0;
    let mut file = temporary.1;

    let result = (|| {
        file.write_all(bytes).map_err(BoundaryError::Io)?;
        file.sync_all().map_err(BoundaryError::Io)?;
        verify_expectation(parent, expected)?;
        before_commit();
        parent
            .dir
            .rename(&temporary_name, &parent.dir, &parent.final_component)
            .map_err(BoundaryError::Io)?;
        sync_parent(parent)?;
        open_existing_regular(parent).map(|opened| opened.identity())
    })();

    if result.is_err() {
        let _ = parent.dir.remove_file(&temporary_name);
    }
    result
}

fn acquire_replace_lock(parent: &OpenedParent) -> Result<std::fs::File, BoundaryError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .follow(FollowSymlinks::No)
        .nonblock(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = parent
        .dir
        .open_with(REPLACE_LOCK_NAME, &options)
        .map_err(|error| map_open_error(&parent.dir, OsStr::new(REPLACE_LOCK_NAME), error))?;
    if !file.metadata().map_err(BoundaryError::Io)?.is_file() {
        return Err(BoundaryError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use cap_std::fs::{Permissions, PermissionsExt as _};
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(BoundaryError::Io)?;
    }
    let file = file.into_std();
    fs4::FileExt::lock(&file).map_err(BoundaryError::Io)?;
    Ok(file)
}

#[cfg(unix)]
fn sync_parent(parent: &OpenedParent) -> Result<(), BoundaryError> {
    // cap-std directory capabilities use O_PATH on Linux, which cannot be
    // fsynced. Reopen the already-held directory capability with read access.
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let directory = parent
        .dir
        .open_with(".", &options)
        .map_err(BoundaryError::Io)?;
    if !directory.metadata().map_err(BoundaryError::Io)?.is_dir() {
        return Err(BoundaryError::Io(io::Error::other(
            "opened parent is not a directory",
        )));
    }
    directory.into_std().sync_all().map_err(BoundaryError::Io)
}

#[cfg(not(unix))]
const fn sync_parent(_parent: &OpenedParent) -> Result<(), BoundaryError> {
    // Windows does not provide a portable directory fsync operation. The
    // temporary file itself is durable before the atomic replacement.
    Ok(())
}

fn opened_regular(file: cap_std::fs::File) -> Result<OpenedRegularFile, BoundaryError> {
    let metadata = file.metadata().map_err(BoundaryError::Io)?;
    if !metadata.is_file() {
        return Err(BoundaryError::NotRegularFile);
    }
    let object = FileObjectIdentity::from_metadata(&metadata);
    Ok(OpenedRegularFile {
        file,
        metadata,
        object,
    })
}

fn verify_expectation(
    parent: &OpenedParent,
    expected: ReplaceExpectation,
) -> Result<(), BoundaryError> {
    match open_existing_regular(parent) {
        Ok(opened) => match expected {
            ReplaceExpectation::Missing => Err(BoundaryError::IdentityMismatch),
            ReplaceExpectation::Matches(identity) if identity != opened.identity() => {
                Err(BoundaryError::IdentityMismatch)
            }
            ReplaceExpectation::Matches(_) | ReplaceExpectation::Any => Ok(()),
        },
        Err(BoundaryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            match expected {
                ReplaceExpectation::Missing | ReplaceExpectation::Any => Ok(()),
                ReplaceExpectation::Matches(_) => Err(BoundaryError::IdentityMismatch),
            }
        }
        Err(error) => Err(error),
    }
}

fn create_private_temporary(
    parent: &OpenedParent,
) -> Result<(OsString, cap_std::fs::File), BoundaryError> {
    for _ in 0..16 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| {
            BoundaryError::Io(io::Error::other("operating system entropy unavailable"))
        })?;
        let name = OsString::from(format!(
            ".kirje-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.tmp",
            random[0],
            random[1],
            random[2],
            random[3],
            random[4],
            random[5],
            random[6],
            random[7],
            random[8],
            random[9],
            random[10],
            random[11],
            random[12],
            random[13],
            random[14],
            random[15]
        ));
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No)
            .nonblock(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match parent.dir.open_with(&name, &options) {
            Ok(file) => return Ok((name, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(BoundaryError::Io(error)),
        }
    }
    Err(BoundaryError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary file",
    )))
}

fn map_open_error(dir: &Dir, final_component: &OsStr, error: io::Error) -> BoundaryError {
    if dir
        .symlink_metadata(final_component)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        BoundaryError::LinkRejected
    } else {
        BoundaryError::Io(error)
    }
}

fn validate_final_component(component: &OsStr) -> Result<(), BoundaryError> {
    let path = Path::new(component);
    if !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.components().nth(1).is_some()
    {
        return Err(BoundaryError::InvalidPath);
    }
    if !platform_component_is_valid(component) {
        return Err(BoundaryError::InvalidPath);
    }
    Ok(())
}

#[cfg(windows)]
fn platform_component_is_valid(component: &OsStr) -> bool {
    let value = component.to_string_lossy();
    let trimmed = value.trim_end_matches([' ', '.']);
    let stem = trimmed.split('.').next().unwrap_or_default();
    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    trimmed.len() == value.len()
        && !value.contains(':')
        && !reserved.iter().any(|name| stem.eq_ignore_ascii_case(name))
}

#[cfg(not(windows))]
const fn platform_component_is_valid(_component: &OsStr) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::{sync::mpsc, time::Duration};

    #[test]
    fn bounded_reader_accepts_exact_limit_and_rejects_one_more() {
        assert_eq!(
            read_stream_bounded(&mut Cursor::new(b"abcd"), 4).expect("exact limit"),
            b"abcd"
        );
        assert!(matches!(
            read_stream_bounded(&mut Cursor::new(b"abcde"), 4),
            Err(BoundaryError::ResourceLimit { limit: 4 })
        ));
    }

    #[test]
    fn opened_handle_is_stable_across_path_replacement() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("message.eml");
        std::fs::write(&path, b"first").expect("seed file");
        let parent = open_parent(&path).expect("parent");
        let mut opened = open_existing_regular(&parent).expect("opened");
        std::fs::rename(&path, directory.path().join("old.eml")).expect("rename");
        std::fs::write(&path, b"second").expect("replacement");
        assert_eq!(read_bounded(&mut opened, 16).expect("read"), b"first");
    }

    #[test]
    fn private_replacement_enforces_identity() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, b"one").expect("seed file");
        let parent = open_parent(&path).expect("parent");
        let original = open_existing_regular(&parent).expect("opened").identity();
        let replacement = replace_private(&parent, ReplaceExpectation::Matches(original), b"two")
            .expect("replace");
        assert_ne!(replacement, original);
        assert_eq!(std::fs::read(path).expect("read"), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(directory.path().join(REPLACE_LOCK_NAME))
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(matches!(
            replace_private(&parent, ReplaceExpectation::Matches(original), b"stale"),
            Err(BoundaryError::IdentityMismatch)
        ));
    }

    #[test]
    fn concurrent_replacements_have_one_compare_and_swap_winner() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        std::fs::write(&path, b"original").expect("seed file");
        let parent = open_parent(&path).expect("parent");
        let original = open_existing_regular(&parent).expect("opened").identity();
        let (at_commit_tx, at_commit_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_path = path.clone();
        let first = std::thread::spawn(move || {
            let parent = open_parent(&first_path).expect("first parent");
            replace_private_inner(
                &parent,
                ReplaceExpectation::Matches(original),
                b"first",
                || {
                    at_commit_tx.send(()).expect("signal first commit");
                    release_rx.recv().expect("release first commit");
                },
            )
        });

        at_commit_rx.recv().expect("first reached commit");
        let (second_tx, second_rx) = mpsc::channel();
        let second = std::thread::spawn(move || {
            let parent = open_parent(&path).expect("second parent");
            let result = replace_private(&parent, ReplaceExpectation::Matches(original), b"second");
            second_tx.send(result).expect("send second result");
        });

        assert!(second_rx.recv_timeout(Duration::from_millis(250)).is_err());
        release_tx.send(()).expect("release first");
        assert!(first.join().expect("first result").is_ok());
        assert!(matches!(
            second_rx.recv().expect("second result"),
            Err(BoundaryError::IdentityMismatch)
        ));
        second.join().expect("second join");
    }

    #[test]
    fn directories_are_not_regular_inputs() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("nested");
        std::fs::create_dir(&path).expect("directory");
        let parent = open_parent(&path).expect("parent");
        assert!(matches!(
            open_existing_regular(&parent),
            Err(BoundaryError::NotRegularFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn final_component_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let target = directory.path().join("target");
        let link = directory.path().join("link");
        std::fs::write(&target, b"secret").expect("target");
        symlink(&target, &link).expect("symlink");
        let parent = open_parent(&link).expect("parent");
        assert!(matches!(
            open_existing_regular(&parent),
            Err(BoundaryError::LinkRejected)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn linked_replace_lock_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("config.toml");
        let lock_target = directory.path().join("lock-target");
        std::fs::write(&path, b"original").expect("seed file");
        std::fs::write(&lock_target, b"target").expect("seed lock target");
        symlink(&lock_target, directory.path().join(REPLACE_LOCK_NAME)).expect("lock symlink");
        let parent = open_parent(&path).expect("parent");
        let original = open_existing_regular(&parent).expect("opened").identity();
        assert!(matches!(
            replace_private(
                &parent,
                ReplaceExpectation::Matches(original),
                b"replacement"
            ),
            Err(BoundaryError::LinkRejected)
        ));
        assert_eq!(std::fs::read(lock_target).expect("lock target"), b"target");
    }
}
