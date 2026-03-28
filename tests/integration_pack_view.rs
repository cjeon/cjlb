//! Integration test: pack a directory tree, then read it back via BundleReader
//! and verify every file is byte-identical to the original.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use tempfile::TempDir;

use cjlb_crypto::MasterKey;
use cjlb_format::chunk::CHUNK_MAGIC;
use cjlb_format::manifest::{MANIFEST_MAGIC, MANIFEST_PREAMBLE_SIZE};
use cjlb_format::page::PAGE_BODY_SIZE;
use cjlb_format::page::PAGE_TOTAL_SIZE;
use cjlb_pack::pack::{run_pack, PackConfig};
use cjlb_view::bundle::{BundleReader, ResolvedPath};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a hex string into raw bytes.
fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Recursively collect all files under `dir` into a map of (relative_path -> contents).
fn collect_files(base: &Path, dir: &Path) -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(base)
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            let data = fs::read(entry.path()).unwrap();
            map.insert(rel, data);
        }
    }
    map
}

/// Walk the bundle's directory tree via BundleReader and collect all files
/// as (relative_path -> decrypted_contents).
fn collect_bundle_files(reader: &BundleReader) -> HashMap<String, Vec<u8>> {
    let mut map = HashMap::new();
    collect_bundle_dir(reader, 0, String::new(), &mut map);
    map
}

fn collect_bundle_dir(
    reader: &BundleReader,
    dir_idx: usize,
    prefix: String,
    map: &mut HashMap<String, Vec<u8>>,
) {
    let dir = reader.dir_entry(dir_idx);
    let (child_dirs, child_files) = reader.dir_children(dir);

    for child_file in child_files {
        let name = reader.file_name(child_file, dir).unwrap();
        let rel = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let data = reader.read_file(child_file).unwrap();
        map.insert(rel, data);
    }

    for (j, child_dir) in child_dirs.iter().enumerate() {
        let child_name = reader.dir_name(child_dir).unwrap();
        let child_prefix = if prefix.is_empty() {
            child_name.to_string()
        } else {
            format!("{prefix}/{child_name}")
        };
        let child_dir_idx = dir.first_child_dir as usize + j;
        collect_bundle_dir(reader, child_dir_idx, child_prefix, map);
    }
}

/// Pack a directory and open the resulting bundle. Returns (reader, master_key, output_dir).
fn pack_and_open(input_dir: &Path) -> (BundleReader, MasterKey, TempDir) {
    let output = TempDir::new().unwrap();
    let config = PackConfig {
        input_dir: input_dir.to_str().unwrap().to_string(),
        output_dir: output.path().to_str().unwrap().to_string(),
        log_level: None,
    };

    let result = run_pack(&config).unwrap();
    let key_bytes: [u8; 32] = hex_decode(&result.master_key_hex).try_into().unwrap();
    let master_key = MasterKey::from_bytes(key_bytes);
    let reader = BundleReader::open(output.path(), &master_key).unwrap();

    (reader, master_key, output)
}

// ---------------------------------------------------------------------------
// Test data setup
// ---------------------------------------------------------------------------

/// Create the canonical test directory with a variety of file sizes and names.
fn create_test_tree(root: &Path) {
    // configs.json at root
    fs::write(
        root.join("configs.json"),
        r#"{"version": 1, "name": "test-bundle"}"#,
    )
    .unwrap();

    // Small files (~100 bytes) in various subdirectories
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(
        root.join("src/main.rs"),
        "fn main() { println!(\"hello\"); }\n".repeat(3),
    )
    .unwrap();
    fs::write(
        root.join("src/lib.rs"),
        b"pub mod core;\npub mod utils;\n// padding to reach ~100 bytes xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
    )
    .unwrap();

    fs::create_dir_all(root.join("data/nested")).unwrap();
    fs::write(root.join("data/readme.txt"), vec![b'A'; 100]).unwrap();
    fs::write(root.join("data/nested/deep.bin"), vec![0xFFu8; 128]).unwrap();

    // Medium file (~500 KB)
    let medium = vec![0xCDu8; 500_000];
    fs::write(root.join("data/medium.bin"), &medium).unwrap();

    // Large file (>1 MiB, spans multiple pages)
    // PAGE_BODY_SIZE is 1 MiB. Make a file that is 2.5 MiB to span 3 pages.
    let large_size = PAGE_BODY_SIZE * 2 + PAGE_BODY_SIZE / 2; // 2.5 MiB
    let large: Vec<u8> = (0..large_size).map(|i| (i % 251) as u8).collect();
    fs::write(root.join("large_file.dat"), &large).unwrap();

    // Empty subdirectory
    fs::create_dir_all(root.join("empty_dir")).unwrap();

    // Files with special names
    fs::create_dir_all(root.join("special")).unwrap();
    fs::write(root.join("special/file with spaces.txt"), b"spaces in name").unwrap();
    fs::write(
        root.join("special/\u{00e9}l\u{00e8}ve.txt"),
        b"unicode filename",
    )
    .unwrap();
    fs::write(root.join("special/UPPER.TXT"), b"uppercase extension").unwrap();
    fs::write(root.join("special/.hidden"), b"dot-prefixed file").unwrap();
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn roundtrip_full_tree() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let original_files = collect_files(input.path(), input.path());
    assert!(
        original_files.len() >= 10,
        "expected at least 10 files, got {}",
        original_files.len()
    );

    let (reader, _master_key, _output) = pack_and_open(input.path());
    let bundle_files = collect_bundle_files(&reader);

    // Every original file must be present in the bundle and byte-identical.
    for (rel_path, original_data) in &original_files {
        let bundle_data = bundle_files
            .get(rel_path)
            .unwrap_or_else(|| panic!("file missing from bundle: {rel_path}"));
        assert_eq!(
            original_data.len(),
            bundle_data.len(),
            "size mismatch for {rel_path}: original {} vs bundle {}",
            original_data.len(),
            bundle_data.len()
        );
        assert_eq!(
            original_data, bundle_data,
            "content mismatch for {rel_path}"
        );
    }

    // No extra files in bundle.
    assert_eq!(
        original_files.len(),
        bundle_files.len(),
        "file count mismatch: original {} vs bundle {}",
        original_files.len(),
        bundle_files.len()
    );
}

#[test]
fn roundtrip_resolve_path() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (reader, _master_key, _output) = pack_and_open(input.path());

    // Root resolves to Dir(0).
    assert!(matches!(
        reader.resolve_path("/").unwrap(),
        ResolvedPath::Dir(0)
    ));
    assert!(matches!(
        reader.resolve_path("").unwrap(),
        ResolvedPath::Dir(0)
    ));

    // Known directories resolve.
    assert!(matches!(
        reader.resolve_path("src").unwrap(),
        ResolvedPath::Dir(_)
    ));
    assert!(matches!(
        reader.resolve_path("data").unwrap(),
        ResolvedPath::Dir(_)
    ));
    assert!(matches!(
        reader.resolve_path("data/nested").unwrap(),
        ResolvedPath::Dir(_)
    ));
    assert!(matches!(
        reader.resolve_path("special").unwrap(),
        ResolvedPath::Dir(_)
    ));
    assert!(matches!(
        reader.resolve_path("empty_dir").unwrap(),
        ResolvedPath::Dir(_)
    ));

    // Known files resolve.
    assert!(matches!(
        reader.resolve_path("configs.json").unwrap(),
        ResolvedPath::File { .. }
    ));
    assert!(matches!(
        reader.resolve_path("src/main.rs").unwrap(),
        ResolvedPath::File { .. }
    ));
    assert!(matches!(
        reader.resolve_path("data/nested/deep.bin").unwrap(),
        ResolvedPath::File { .. }
    ));
    assert!(matches!(
        reader.resolve_path("large_file.dat").unwrap(),
        ResolvedPath::File { .. }
    ));
    assert!(matches!(
        reader.resolve_path("special/file with spaces.txt").unwrap(),
        ResolvedPath::File { .. }
    ));
    assert!(matches!(
        reader
            .resolve_path("special/\u{00e9}l\u{00e8}ve.txt")
            .unwrap(),
        ResolvedPath::File { .. }
    ));

    // Nonexistent paths fail.
    assert!(reader.resolve_path("nonexistent.txt").is_err());
    assert!(reader.resolve_path("src/nonexistent.rs").is_err());
    assert!(reader.resolve_path("no/such/dir/file.txt").is_err());
}

#[test]
fn roundtrip_read_individual_files() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (reader, _master_key, _output) = pack_and_open(input.path());

    // Read configs.json via resolve_path + read_file.
    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("configs.json").unwrap() {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        let expected = fs::read(input.path().join("configs.json")).unwrap();
        assert_eq!(data, expected);
    } else {
        panic!("configs.json should resolve to a file");
    }

    // Read the large file (multi-page).
    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("large_file.dat").unwrap() {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        let expected = fs::read(input.path().join("large_file.dat")).unwrap();
        assert_eq!(data.len(), expected.len(), "large file size mismatch");
        assert_eq!(data, expected, "large file content mismatch");
    } else {
        panic!("large_file.dat should resolve to a file");
    }

    // Read the medium file.
    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("data/medium.bin").unwrap() {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        let expected = fs::read(input.path().join("data/medium.bin")).unwrap();
        assert_eq!(data, expected);
    } else {
        panic!("data/medium.bin should resolve to a file");
    }
}

#[test]
fn roundtrip_directory_listing() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (reader, _master_key, _output) = pack_and_open(input.path());

    // Root directory should contain expected child dirs and files.
    let root = reader.root_dir();
    let (child_dirs, child_files) = reader.dir_children(root);

    let dir_names: Vec<&str> = child_dirs
        .iter()
        .map(|d| reader.dir_name(d).unwrap())
        .collect();
    let file_names: Vec<&str> = child_files
        .iter()
        .map(|f| reader.file_name(f, root).unwrap())
        .collect();

    // Expected root-level directories.
    assert!(dir_names.contains(&"src"), "root should contain src/");
    assert!(dir_names.contains(&"data"), "root should contain data/");
    assert!(
        dir_names.contains(&"special"),
        "root should contain special/"
    );
    assert!(
        dir_names.contains(&"empty_dir"),
        "root should contain empty_dir/"
    );

    // Expected root-level files.
    assert!(
        file_names.contains(&"configs.json"),
        "root should contain configs.json"
    );
    assert!(
        file_names.contains(&"large_file.dat"),
        "root should contain large_file.dat"
    );

    // empty_dir should have no children.
    if let ResolvedPath::Dir(idx) = reader.resolve_path("empty_dir").unwrap() {
        let dir = reader.dir_entry(idx);
        let (sub_dirs, sub_files) = reader.dir_children(dir);
        assert!(sub_dirs.is_empty(), "empty_dir should have no child dirs");
        assert!(sub_files.is_empty(), "empty_dir should have no files");
    } else {
        panic!("empty_dir should resolve to a directory");
    }
}

#[test]
fn bundle_structure_manifest_magic() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (_reader, _master_key, output) = pack_and_open(input.path());

    // manifest.enc exists and starts with "CJLBM" magic.
    let manifest_path = output.path().join("manifest.enc");
    assert!(manifest_path.exists(), "manifest.enc must exist");
    let manifest_data = fs::read(&manifest_path).unwrap();
    assert!(
        manifest_data.len() >= MANIFEST_PREAMBLE_SIZE,
        "manifest too short"
    );
    assert_eq!(
        &manifest_data[0..4],
        &MANIFEST_MAGIC,
        "manifest magic mismatch"
    );

    // After preamble, remaining bytes are pages (each PAGE_TOTAL_SIZE).
    let after_preamble = manifest_data.len() - MANIFEST_PREAMBLE_SIZE;
    assert_eq!(
        after_preamble % PAGE_TOTAL_SIZE,
        0,
        "manifest page data not aligned to PAGE_TOTAL_SIZE"
    );
}

#[test]
fn bundle_structure_chunks() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (_reader, _master_key, output) = pack_and_open(input.path());

    // chunks/ directory exists.
    let chunks_dir = output.path().join("chunks");
    assert!(chunks_dir.is_dir(), "chunks/ directory must exist");

    // At least one .enc file.
    let chunk_files: Vec<_> = fs::read_dir(&chunks_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "enc")
                .unwrap_or(false)
        })
        .collect();
    assert!(!chunk_files.is_empty(), "must have at least one chunk file");

    // Each chunk file starts with "CJLBC" magic.
    for entry in &chunk_files {
        let data = fs::read(entry.path()).unwrap();
        assert!(
            data.len() >= 48,
            "chunk file {:?} too short",
            entry.file_name()
        );
        assert_eq!(
            &data[0..4],
            &CHUNK_MAGIC,
            "chunk {:?} magic mismatch",
            entry.file_name()
        );

        // Payload after 48-byte header is N * PAGE_TOTAL_SIZE.
        let payload = data.len() - 48;
        assert_eq!(
            payload % PAGE_TOTAL_SIZE,
            0,
            "chunk {:?} payload not page-aligned",
            entry.file_name()
        );
    }
}

#[test]
fn bundle_structure_key_commitment() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let output = TempDir::new().unwrap();
    let config = PackConfig {
        input_dir: input.path().to_str().unwrap().to_string(),
        output_dir: output.path().to_str().unwrap().to_string(),
        log_level: None,
    };
    let result = run_pack(&config).unwrap();
    let key_bytes: [u8; 32] = hex_decode(&result.master_key_hex).try_into().unwrap();
    let master_key = MasterKey::from_bytes(key_bytes);

    // Read the preamble and verify key_commit field matches.
    let manifest_data = fs::read(output.path().join("manifest.enc")).unwrap();
    // key_commit is at offset 32 in the preamble: magic(4) + version(4) + header_pages(4) + rt_pages(4) + bundle_id(16) = 32.
    let stored_commit: [u8; 32] = manifest_data[32..64].try_into().unwrap();
    let expected_commit = master_key.key_commit();
    assert_eq!(
        stored_commit, expected_commit,
        "key commitment in preamble must match"
    );
}

#[test]
fn wrong_key_fails_to_open() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (_reader, _master_key, output) = pack_and_open(input.path());

    // Attempting to open with a different key should fail.
    let wrong_key = MasterKey::from_bytes([0xBA; 32]);
    let result = BundleReader::open(output.path(), &wrong_key);
    assert!(result.is_err(), "wrong key must fail to open bundle");
    let err_msg = format!("{}", result.err().unwrap());
    assert!(
        err_msg.contains("key commitment mismatch"),
        "error should mention key commitment, got: {err_msg}"
    );
}

#[test]
fn roundtrip_empty_directory() {
    let input = TempDir::new().unwrap();
    // Pack a completely empty directory.
    let (reader, _master_key, _output) = pack_and_open(input.path());

    assert_eq!(reader.file_count(), 0, "empty dir should have 0 files");
    // Root dir always exists.
    assert!(reader.dir_count() >= 1, "must have at least root dir");
}

#[test]
fn roundtrip_single_empty_file() {
    let input = TempDir::new().unwrap();
    fs::write(input.path().join("empty.txt"), b"").unwrap();

    let (reader, _master_key, _output) = pack_and_open(input.path());

    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("empty.txt").unwrap() {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert!(data.is_empty(), "empty file should read back as empty");
    } else {
        panic!("empty.txt should resolve to a file");
    }
}

#[test]
fn roundtrip_file_exactly_one_page() {
    let input = TempDir::new().unwrap();
    // File that is exactly PAGE_BODY_SIZE (1 MiB) -- boundary case.
    let data = vec![0x42u8; PAGE_BODY_SIZE];
    fs::write(input.path().join("exact_page.bin"), &data).unwrap();

    let (reader, _master_key, _output) = pack_and_open(input.path());

    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("exact_page.bin").unwrap() {
        let read_back = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert_eq!(read_back.len(), PAGE_BODY_SIZE);
        assert_eq!(read_back, data);
    } else {
        panic!("exact_page.bin should resolve to a file");
    }
}

#[test]
fn roundtrip_file_one_byte_over_page() {
    let input = TempDir::new().unwrap();
    // File that is PAGE_BODY_SIZE + 1 -- forces multi-page (large file path).
    let size = PAGE_BODY_SIZE + 1;
    let data: Vec<u8> = (0..size).map(|i| (i % 199) as u8).collect();
    fs::write(input.path().join("over_page.bin"), &data).unwrap();

    let (reader, _master_key, _output) = pack_and_open(input.path());

    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("over_page.bin").unwrap() {
        let read_back = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert_eq!(read_back.len(), size);
        assert_eq!(read_back, data);
    } else {
        panic!("over_page.bin should resolve to a file");
    }
}

#[test]
fn roundtrip_special_filenames() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let (reader, _master_key, _output) = pack_and_open(input.path());

    // File with spaces.
    if let ResolvedPath::File { file_idx, .. } =
        reader.resolve_path("special/file with spaces.txt").unwrap()
    {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert_eq!(data, b"spaces in name");
    } else {
        panic!("special/file with spaces.txt should resolve");
    }

    // Unicode filename.
    if let ResolvedPath::File { file_idx, .. } = reader
        .resolve_path("special/\u{00e9}l\u{00e8}ve.txt")
        .unwrap()
    {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert_eq!(data, b"unicode filename");
    } else {
        panic!("unicode filename should resolve");
    }

    // Hidden file.
    if let ResolvedPath::File { file_idx, .. } = reader.resolve_path("special/.hidden").unwrap() {
        let data = reader.read_file(&reader.files()[file_idx]).unwrap();
        assert_eq!(data, b"dot-prefixed file");
    } else {
        panic!(".hidden should resolve");
    }
}

#[test]
fn metadata_counts_match() {
    let input = TempDir::new().unwrap();
    create_test_tree(input.path());

    let original_files = collect_files(input.path(), input.path());
    let (reader, _master_key, _output) = pack_and_open(input.path());

    assert_eq!(
        reader.file_count() as usize,
        original_files.len(),
        "file_count should match number of files on disk"
    );

    // Count directories on disk (including root).
    let disk_dirs: usize = walkdir::WalkDir::new(input.path())
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_dir())
        .count();
    assert_eq!(
        reader.dir_count() as usize,
        disk_dirs,
        "dir_count should match"
    );
}
