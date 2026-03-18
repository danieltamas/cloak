//! Integration tests for `platform.rs`.

use cloak::platform;
use std::path::PathBuf;

/// config_dir() returns the correct platform-specific path.
#[test]
fn test_config_dir_correct_path() {
    let dir = platform::config_dir().expect("config_dir should succeed");

    // The path must end with "cloak" as the last component.
    let last = dir
        .file_name()
        .expect("config_dir path should have a file name");
    assert_eq!(
        last, "cloak",
        "Last component should be 'cloak', got {:?}",
        dir
    );

    // On macOS the path should contain "Application Support".
    #[cfg(target_os = "macos")]
    {
        let s = dir.to_string_lossy();
        assert!(
            s.contains("Application Support"),
            "macOS config_dir should contain 'Application Support', got {}",
            s
        );
    }

    // On Linux the path should contain ".config".
    #[cfg(target_os = "linux")]
    {
        let s = dir.to_string_lossy();
        assert!(
            s.contains(".config"),
            "Linux config_dir should contain '.config', got {}",
            s
        );
    }

    // On Windows the path should contain "AppData".
    #[cfg(windows)]
    {
        let s = dir.to_string_lossy();
        assert!(
            s.contains("AppData"),
            "Windows config_dir should contain 'AppData', got {}",
            s
        );
    }
}

/// config_dir() creates the directory if it does not already exist.
#[test]
fn test_config_dir_creates_directory() {
    // Calling config_dir() should always leave the directory present.
    let dir = platform::config_dir().expect("config_dir should succeed");
    assert!(
        dir.exists(),
        "config_dir should exist after calling config_dir(), path: {}",
        dir.display()
    );
    assert!(dir.is_dir(), "config_dir path should be a directory");
}

/// set_private_permissions() sets mode 0o600 on Unix.
#[test]
fn test_set_private_permissions() {
    use std::io::Write;
    let tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
    let path = tmp.path();

    // Write something so the file definitely exists.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("failed to open temp file");
    f.write_all(b"secret").expect("failed to write");
    drop(f);

    platform::set_private_permissions(path).expect("set_private_permissions should succeed");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).expect("failed to read metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "Expected mode 0o600, got 0o{:o}", mode);
    }

    // On Windows the call is a no-op; just verify it doesn't error.
    #[cfg(windows)]
    {
        // Nothing to assert beyond no panic/error.
        let _ = path;
    }
}

/// secure_delete() overwrites the file and then removes it.
#[test]
fn test_secure_delete_removes_file() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let file_path = dir.path().join("sensitive.dat");

    {
        let mut f = std::fs::File::create(&file_path).expect("failed to create file");
        f.write_all(b"TOP SECRET DATA 1234567890")
            .expect("failed to write");
    }

    assert!(file_path.exists(), "File should exist before secure_delete");

    platform::secure_delete(&file_path).expect("secure_delete should succeed");

    assert!(
        !file_path.exists(),
        "File should not exist after secure_delete"
    );
}

/// secure_temp_dir() returns /dev/shm on Linux when available, temp dir otherwise.
#[test]
fn test_secure_temp_dir() {
    let tmp = platform::secure_temp_dir().expect("secure_temp_dir should succeed");

    assert!(
        tmp.exists(),
        "secure_temp_dir path should exist: {}",
        tmp.display()
    );

    #[cfg(target_os = "linux")]
    {
        let shm = PathBuf::from("/dev/shm");
        if shm.exists() {
            assert_eq!(
                tmp, shm,
                "On Linux with /dev/shm present, secure_temp_dir should return /dev/shm"
            );
        } else {
            // /dev/shm not present; must fall back to system temp.
            assert_ne!(
                tmp.to_string_lossy(),
                "/dev/shm",
                "Should not return /dev/shm when it does not exist"
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux platforms, must NOT return /dev/shm.
        assert_ne!(
            tmp,
            PathBuf::from("/dev/shm"),
            "Non-Linux platform should not return /dev/shm"
        );
    }
}
