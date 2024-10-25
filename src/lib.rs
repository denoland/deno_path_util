// Copyright 2018-2024 the Deno authors. MIT license.

#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(clippy::unused_async)]

use std::io::ErrorKind;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use thiserror::Error;
use url::Url;

/// Gets the parent of this url.
pub fn url_parent(url: &Url) -> Url {
  let mut url = url.clone();
  // don't use url.segments() because it will strip the leading slash
  let mut segments = url.path().split('/').collect::<Vec<_>>();
  if segments.iter().all(|s| s.is_empty()) {
    return url;
  }
  if let Some(last) = segments.last() {
    if last.is_empty() {
      segments.pop();
    }
    segments.pop();
    let new_path = format!("{}/", segments.join("/"));
    url.set_path(&new_path);
  }
  url
}

#[derive(Debug, Error)]
#[error("Could not convert URL to file path.\n  URL: {0}")]
pub struct UrlToFilePathError(pub Url);

/// Attempts to convert a url to a file path. By default, uses the Url
/// crate's `to_file_path()` method, but falls back to try and resolve unix-style
/// paths on Windows.
pub fn url_to_file_path(url: &Url) -> Result<PathBuf, UrlToFilePathError> {
  let result = if url.scheme() != "file" {
    Err(())
  } else {
    url_to_file_path_inner(url)
  };
  match result {
    Ok(path) => Ok(path),
    Err(()) => Err(UrlToFilePathError(url.clone())),
  }
}

fn url_to_file_path_inner(url: &Url) -> Result<PathBuf, ()> {
  #[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
  return url_to_file_path_real(url);
  #[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
  url_to_file_path_wasm(url)
}

#[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
fn url_to_file_path_real(url: &Url) -> Result<PathBuf, ()> {
  if cfg!(windows) {
    match url.to_file_path() {
      Ok(path) => Ok(path),
      Err(()) => {
        // This might be a unix-style path which is used in the tests even on Windows.
        // Attempt to see if we can convert it to a `PathBuf`. This code should be removed
        // once/if https://github.com/servo/rust-url/issues/730 is implemented.
        if url.scheme() == "file"
          && url.host().is_none()
          && url.port().is_none()
          && url.path_segments().is_some()
        {
          let path_str = url.path();
          match String::from_utf8(
            percent_encoding::percent_decode(path_str.as_bytes()).collect(),
          ) {
            Ok(path_str) => Ok(PathBuf::from(path_str)),
            Err(_) => Err(()),
          }
        } else {
          Err(())
        }
      }
    }
  } else {
    url.to_file_path()
  }
}

#[cfg(any(
  test,
  not(any(unix, windows, target_os = "redox", target_os = "wasi"))
))]
fn url_to_file_path_wasm(url: &Url) -> Result<PathBuf, ()> {
  fn is_windows_path_segment(url: &str) -> bool {
    let mut chars = url.chars();

    let first_char = chars.next();
    if first_char.is_none() || !first_char.unwrap().is_ascii_alphabetic() {
      return false;
    }

    if chars.next() != Some(':') {
      return false;
    }

    chars.next().is_none()
  }

  let path_segments = url.path_segments().unwrap().collect::<Vec<_>>();
  let mut final_text = String::new();
  let mut is_windows_share = false;
  if let Some(host) = url.host_str() {
    final_text.push_str("\\\\");
    final_text.push_str(host);
    is_windows_share = true;
  }
  for segment in path_segments.iter() {
    if is_windows_share {
      final_text.push('\\');
    } else if !final_text.is_empty() {
      final_text.push('/');
    }
    final_text.push_str(
      &percent_encoding::percent_decode_str(segment).decode_utf8_lossy(),
    );
  }
  if !is_windows_share && !is_windows_path_segment(path_segments[0]) {
    final_text = format!("/{}", final_text);
  }
  Ok(PathBuf::from(final_text))
}

/// Normalize all intermediate components of the path (ie. remove "./" and "../" components).
/// Similar to `fs::canonicalize()` but doesn't resolve symlinks.
///
/// Taken from Cargo
/// <https://github.com/rust-lang/cargo/blob/af307a38c20a753ec60f0ad18be5abed3db3c9ac/src/cargo/util/paths.rs#L60-L85>
#[inline]
pub fn normalize_path<P: AsRef<Path>>(path: P) -> PathBuf {
  fn inner(path: &Path) -> PathBuf {
    let mut components = path.components().peekable();
    let mut ret =
      if let Some(c @ Component::Prefix(..)) = components.peek().cloned() {
        components.next();
        PathBuf::from(c.as_os_str())
      } else {
        PathBuf::new()
      };

    for component in components {
      match component {
        Component::Prefix(..) => unreachable!(),
        Component::RootDir => {
          ret.push(component.as_os_str());
        }
        Component::CurDir => {}
        Component::ParentDir => {
          ret.pop();
        }
        Component::Normal(c) => {
          ret.push(c);
        }
      }
    }
    ret
  }

  inner(path.as_ref())
}

#[derive(Debug, Error)]
#[error("Could not convert path to URL.\n  Path: {0}")]
pub struct PathToUrlError(pub PathBuf);

#[allow(clippy::result_unit_err)]
pub fn url_from_file_path(path: &Path) -> Result<Url, PathToUrlError> {
  #[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
  return Url::from_file_path(path)
    .map_err(|()| PathToUrlError(path.to_path_buf()));
  #[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
  url_from_file_path_wasm(path).map_err(|()| PathToUrlError(path.to_path_buf()))
}

#[allow(clippy::result_unit_err)]
pub fn url_from_directory_path(path: &Path) -> Result<Url, PathToUrlError> {
  #[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
  return Url::from_directory_path(path)
    .map_err(|()| PathToUrlError(path.to_path_buf()));
  #[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
  url_from_directory_path_wasm(path)
    .map_err(|()| PathToUrlError(path.to_path_buf()))
}

#[cfg(any(
  test,
  not(any(unix, windows, target_os = "redox", target_os = "wasi"))
))]
fn url_from_directory_path_wasm(path: &Path) -> Result<Url, ()> {
  let mut url = url_from_file_path_wasm(path)?;
  url.path_segments_mut().unwrap().push("");
  Ok(url)
}

#[cfg(any(
  test,
  not(any(unix, windows, target_os = "redox", target_os = "wasi"))
))]
fn url_from_file_path_wasm(path: &Path) -> Result<Url, ()> {
  use std::path::Component;

  let original_path = path.to_string_lossy();
  let mut path_str = original_path;
  // assume paths containing backslashes are windows paths
  if path_str.contains('\\') {
    let mut url = Url::parse("file://").unwrap();
    if let Some(next) = path_str.strip_prefix(r#"\\?\UNC\"#) {
      if let Some((host, rest)) = next.split_once('\\') {
        if url.set_host(Some(host)).is_ok() {
          path_str = rest.to_string().into();
        }
      }
    } else if let Some(next) = path_str.strip_prefix(r#"\\?\"#) {
      path_str = next.to_string().into();
    } else if let Some(next) = path_str.strip_prefix(r#"\\"#) {
      if let Some((host, rest)) = next.split_once('\\') {
        if url.set_host(Some(host)).is_ok() {
          path_str = rest.to_string().into();
        }
      }
    }

    for component in path_str.split('\\') {
      url.path_segments_mut().unwrap().push(component);
    }

    Ok(url)
  } else {
    let mut url = Url::parse("file://").unwrap();
    for component in path.components() {
      match component {
        Component::RootDir => {
          url.path_segments_mut().unwrap().push("");
        }
        Component::Normal(segment) => {
          url
            .path_segments_mut()
            .unwrap()
            .push(&segment.to_string_lossy());
        }
        Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
          return Err(());
        }
      }
    }

    Ok(url)
  }
}

/// Gets if the provided url has the specified extension, ignoring case.
pub fn url_has_extension(specifier: &Url, searching_ext: &str) -> bool {
  let searching_ext = searching_ext.strip_prefix('.').unwrap_or(searching_ext);
  debug_assert!(!searching_ext.contains('.')); // exts like .d.ts are not implemented here
  let path = specifier.path();
  if path.len() < searching_ext.len() {
    return false;
  }
  let ext_pos = path.len() - searching_ext.len();
  let (start_path, end_path) = path.split_at(ext_pos);
  end_path.eq_ignore_ascii_case(searching_ext)
    && start_path.ends_with('.')
    && !start_path.ends_with("/.")
}

#[cfg(not(windows))]
#[inline]
pub fn strip_unc_prefix(path: PathBuf) -> PathBuf {
  path
}

/// Strips the unc prefix (ex. \\?\) from Windows paths.
#[cfg(windows)]
pub fn strip_unc_prefix(path: PathBuf) -> PathBuf {
  use std::path::Component;
  use std::path::Prefix;

  let mut components = path.components();
  match components.next() {
    Some(Component::Prefix(prefix)) => {
      match prefix.kind() {
        // \\?\device
        Prefix::Verbatim(device) => {
          let mut path = PathBuf::new();
          path.push(format!(r"\\{}\", device.to_string_lossy()));
          path.extend(components.filter(|c| !matches!(c, Component::RootDir)));
          path
        }
        // \\?\c:\path
        Prefix::VerbatimDisk(_) => {
          let mut path = PathBuf::new();
          path.push(prefix.as_os_str().to_string_lossy().replace(r"\\?\", ""));
          path.extend(components);
          path
        }
        // \\?\UNC\hostname\share_name\path
        Prefix::VerbatimUNC(hostname, share_name) => {
          let mut path = PathBuf::new();
          path.push(format!(
            r"\\{}\{}\",
            hostname.to_string_lossy(),
            share_name.to_string_lossy()
          ));
          path.extend(components.filter(|c| !matches!(c, Component::RootDir)));
          path
        }
        _ => path,
      }
    }
    _ => path,
  }
}

/// Canonicalizes a path which might be non-existent by going up the
/// ancestors until it finds a directory that exists, canonicalizes
/// that path, then adds back the remaining path components.
///
/// Note: When using this, you should be aware that a symlink may
/// subsequently be created along this path by some other code.
pub fn canonicalize_path_maybe_not_exists(
  path: &Path,
  canonicalize: &impl Fn(&Path) -> std::io::Result<PathBuf>,
) -> std::io::Result<PathBuf> {
  let path = normalize_path(path);
  let mut path = path.as_path();
  let mut names_stack = Vec::new();
  loop {
    match canonicalize(path) {
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_url_parent() {
    run_test("file:///", "file:///");
    run_test("file:///test", "file:///");
    run_test("file:///test/", "file:///");
    run_test("file:///test/other", "file:///test/");
    run_test("file:///test/other.txt", "file:///test/");
    run_test("file:///test/other/", "file:///test/");

    fn run_test(url: &str, expected: &str) {
      let result = url_parent(&Url::parse(url).unwrap());
      assert_eq!(result.to_string(), expected);
    }
  }

  #[test]
  fn test_url_to_file_path() {
    run_success_test("file:///", "/");
    run_success_test("file:///test", "/test");
    run_success_test("file:///dir/test/test.txt", "/dir/test/test.txt");
    run_success_test(
      "file:///dir/test%20test/test.txt",
      "/dir/test test/test.txt",
    );

    assert_no_panic_url_to_file_path("file:/");
    assert_no_panic_url_to_file_path("file://");
    assert_no_panic_url_to_file_path("file://asdf/");
    assert_no_panic_url_to_file_path("file://asdf/66666/a.ts");

    fn run_success_test(url: &str, expected_path: &str) {
      let result = url_to_file_path(&Url::parse(url).unwrap()).unwrap();
      assert_eq!(result, PathBuf::from(expected_path));
    }

    fn assert_no_panic_url_to_file_path(url: &str) {
      let _result = url_to_file_path(&Url::parse(url).unwrap());
    }
  }

  #[test]
  fn test_url_to_file_path_wasm() {
    #[track_caller]
    fn convert(path: &str) -> String {
      url_to_file_path_wasm(&Url::parse(path).unwrap())
        .unwrap()
        .to_string_lossy()
        .into_owned()
    }

    assert_eq!(convert("file:///a/b/c.json"), "/a/b/c.json");
    assert_eq!(convert("file:///D:/test/other.json"), "D:/test/other.json");
    assert_eq!(
      convert("file:///path%20with%20spaces/and%23special%25chars!.json"),
      "/path with spaces/and#special%chars!.json",
    );
    assert_eq!(
      convert("file:///C:/My%20Documents/file.txt"),
      "C:/My Documents/file.txt"
    );
    assert_eq!(
      convert("file:///a/b/%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.txt"),
      "/a/b/пример.txt"
    );
    assert_eq!(
      convert("file://server/share/folder/file.txt"),
      "\\\\server\\share\\folder\\file.txt"
    );
  }

  #[test]
  fn test_url_from_file_path_wasm() {
    #[track_caller]
    fn convert(path: &str) -> String {
      url_from_file_path_wasm(Path::new(path))
        .unwrap()
        .to_string()
    }

    assert_eq!(convert("/a/b/c.json"), "file:///a/b/c.json");
    assert_eq!(
      convert("D:\\test\\other.json"),
      "file:///D:/test/other.json"
    );
    assert_eq!(
      convert("/path with spaces/and#special%chars!.json"),
      "file:///path%20with%20spaces/and%23special%25chars!.json"
    );
    assert_eq!(
      convert("C:\\My Documents\\file.txt"),
      "file:///C:/My%20Documents/file.txt"
    );
    assert_eq!(
      convert("/a/b/пример.txt"),
      "file:///a/b/%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80.txt"
    );
    assert_eq!(
      convert("\\\\server\\share\\folder\\file.txt"),
      "file://server/share/folder/file.txt"
    );
    assert_eq!(convert(r#"\\?\UNC\server\share"#), "file://server/share");
    assert_eq!(
      convert(r"\\?\cat_pics\subfolder\file.jpg"),
      "file:///cat_pics/subfolder/file.jpg"
    );
    assert_eq!(convert(r"\\?\cat_pics"), "file:///cat_pics");
  }

  #[test]
  fn test_url_from_directory_path_wasm() {
    #[track_caller]
    fn convert(path: &str) -> String {
      url_from_directory_path_wasm(Path::new(path))
        .unwrap()
        .to_string()
    }

    assert_eq!(convert("/a/b/c"), "file:///a/b/c/");
    assert_eq!(convert("D:\\test\\other"), "file:///D:/test/other/");
  }

  #[test]
  fn test_url_has_extension() {
    fn get(specifier: &str, ext: &str) -> bool {
      url_has_extension(&Url::parse(specifier).unwrap(), ext)
    }

    assert!(get("file:///a/b/c.ts", "ts"));
    assert!(get("file:///a/b/c.ts", ".ts"));
    assert!(!get("file:///a/b/c.ts", ".cts"));
    assert!(get("file:///a/b/c.CtS", ".cts"));
    assert!(get("https://localhost/file.cts", ".cts"));
    assert!(!get("https://localhost/filects", ".cts"));
    assert!(!get("https://localhost/cts", ".cts"));
    // no because this is a hidden file and not an extension
    assert!(!get("file:///a/b/.CtS", ".cts"));
    assert!(!get("https://localhost/.cts", ".cts"));
  }

  #[cfg(windows)]
  #[test]
  fn test_strip_unc_prefix() {
    use std::path::PathBuf;

    run_test(r"C:\", r"C:\");
    run_test(r"C:\test\file.txt", r"C:\test\file.txt");

    run_test(r"\\?\C:\", r"C:\");
    run_test(r"\\?\C:\test\file.txt", r"C:\test\file.txt");

    run_test(r"\\.\C:\", r"\\.\C:\");
    run_test(r"\\.\C:\Test\file.txt", r"\\.\C:\Test\file.txt");

    run_test(r"\\?\UNC\localhost\", r"\\localhost");
    run_test(r"\\?\UNC\localhost\c$\", r"\\localhost\c$");
    run_test(
      r"\\?\UNC\localhost\c$\Windows\file.txt",
      r"\\localhost\c$\Windows\file.txt",
    );
    run_test(r"\\?\UNC\wsl$\deno.json", r"\\wsl$\deno.json");

    run_test(r"\\?\server1", r"\\server1");
    run_test(r"\\?\server1\e$\", r"\\server1\e$\");
    run_test(
      r"\\?\server1\e$\test\file.txt",
      r"\\server1\e$\test\file.txt",
    );

    fn run_test(input: &str, expected: &str) {
      assert_eq!(
        super::strip_unc_prefix(PathBuf::from(input)),
        PathBuf::from(expected)
      );
    }
  }

  #[cfg(windows)]
  #[test]
  fn test_normalize_path() {
    use super::*;

    run_test("C:\\test\\./file.txt", "C:\\test\\file.txt");
    run_test("C:\\test\\../other/file.txt", "C:\\other\\file.txt");
    run_test("C:\\test\\../other\\file.txt", "C:\\other\\file.txt");

    fn run_test(input: &str, expected: &str) {
      assert_eq!(
        normalize_path(PathBuf::from(input)),
        PathBuf::from(expected)
      );
    }
  }
}
