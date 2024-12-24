// Copyright 2018-2024 the Deno authors. MIT license.

use std::io::Error;
use std::io::ErrorKind;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use sys_traits::FsCanonicalize;
use sys_traits::FsCreateDirAll;
use sys_traits::FsFileSetPermissions;
use sys_traits::FsOpen;
use sys_traits::FsRemoveFile;
use sys_traits::FsRename;
use sys_traits::FsSymlinkMetadata;
use sys_traits::OpenOptions;
use sys_traits::SystemRandom;
use sys_traits::ThreadSleep;

use crate::get_atomic_path;
use crate::normalize_path;

/// Canonicalizes a path which might be non-existent by going up the
/// ancestors until it finds a directory that exists, canonicalizes
/// that path, then adds back the remaining path components.
///
/// Note: When using this, you should be aware that a symlink may
/// subsequently be created along this path by some other code.
pub fn canonicalize_path_maybe_not_exists(
  path: &Path,
  sys: &impl FsCanonicalize,
) -> std::io::Result<PathBuf> {
  let path = normalize_path(path);
  let mut path = path.as_path();
  let mut names_stack = Vec::new();
  loop {
    match sys.fs_canonicalize(path) {
      Ok(mut canonicalized_path) => {
        for name in names_stack.into_iter().rev() {
          canonicalized_path = canonicalized_path.join(name);
        }
        return Ok(canonicalized_path);
      }
      Err(err) if err.kind() == ErrorKind::NotFound => {
        names_stack.push(match path.file_name() {
          Some(name) => name.to_owned(),
          None => return Err(err),
        });
        path = match path.parent() {
          Some(parent) => parent,
          None => return Err(err),
        };
      }
      Err(err) => return Err(err),
    }
  }
}

pub fn atomic_write_file_with_retries<
  TSys: FsCreateDirAll
    + FsSymlinkMetadata
    + FsOpen
    + FsRemoveFile
    + FsRename
    + ThreadSleep
    + SystemRandom,
>(
  sys: &TSys,
  file_path: &Path,
  data: &[u8],
  mode: u32,
) -> std::io::Result<()> {
  let mut count = 0;
  loop {
    match atomic_write_file(sys, file_path, data, mode) {
      Ok(()) => return Ok(()),
      Err(err) => {
        if count >= 5 {
          // too many retries, return the error
          return Err(err);
        }
        count += 1;
        let sleep_ms = std::cmp::min(50, 10 * count);
        sys.thread_sleep(std::time::Duration::from_millis(sleep_ms));
      }
    }
  }
}

/// Writes the file to the file system at a temporary path, then
/// renames it to the destination in a single sys call in order
/// to never leave the file system in a corrupted state.
///
/// This also handles creating the directory if a NotFound error
/// occurs.
pub fn atomic_write_file<
  TSys: FsCreateDirAll
    + FsSymlinkMetadata
    + FsOpen
    + FsRemoveFile
    + FsRename
    + SystemRandom,
>(
  sys: &TSys,
  file_path: &Path,
  data: &[u8],
  mode: u32,
) -> std::io::Result<()> {
  fn atomic_write_file_raw<TSys: FsOpen + FsRename + FsRemoveFile>(
    sys: &TSys,
    temp_file_path: &Path,
    file_path: &Path,
    data: &[u8],
    mode: u32,
  ) -> std::io::Result<()> {
    let mut file = sys.fs_open(temp_file_path, &OpenOptions::write())?;
    file.fs_file_set_permissions(mode)?;
    file.write_all(data)?;
    sys
      .fs_rename(temp_file_path, file_path)
      .inspect_err(|_err| {
        // clean up the created temp file on error
        let _ = sys.fs_remove_file(temp_file_path);
      })
  }

  let temp_file_path = get_atomic_path(sys, file_path);

  if let Err(write_err) =
    atomic_write_file_raw(sys, &temp_file_path, file_path, data, mode)
  {
    if write_err.kind() == ErrorKind::NotFound {
      let parent_dir_path = file_path.parent().unwrap();
      match sys.fs_create_dir_all(parent_dir_path) {
        Ok(()) => {
          return atomic_write_file_raw(
            sys,
            &temp_file_path,
            file_path,
            data,
            mode,
          )
          .map_err(|err| add_file_context_to_err(file_path, err));
        }
        Err(create_err) => {
          if !sys.fs_exists(parent_dir_path).unwrap_or(false) {
            return Err(Error::new(
              create_err.kind(),
              format!(
                "{:#} (for '{}')\nCheck the permission of the directory.",
                create_err,
                parent_dir_path.display()
              ),
            ));
          }
        }
      }
    }
    return Err(add_file_context_to_err(file_path, write_err));
  }
  Ok(())
}

fn add_file_context_to_err(file_path: &Path, err: Error) -> Error {
  Error::new(
    err.kind(),
    format!("{:#} (for '{}')", err, file_path.display()),
  )
}

#[cfg(test)]
mod test {
  use std::path::PathBuf;

  use sys_traits::impls::InMemorySys;
  use sys_traits::EnvSetCurrentDir;
  use sys_traits::FsCreateDirAll;

  use super::canonicalize_path_maybe_not_exists;

  #[test]
  fn test_canonicalize_path_maybe_not_exists() {
    let sys = InMemorySys::default();
    sys.fs_create_dir_all("/a/b/c").unwrap();
    sys.env_set_current_dir("/a/b").unwrap();
    let path =
      canonicalize_path_maybe_not_exists(&PathBuf::from("./c"), &sys).unwrap();
    assert_eq!(path, PathBuf::from("/a/b/c"));
    let path =
      canonicalize_path_maybe_not_exists(&PathBuf::from("./c/d/e"), &sys)
        .unwrap();
    assert_eq!(path, PathBuf::from("/a/b/c/d/e"));
  }
}
