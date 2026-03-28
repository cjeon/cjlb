use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::bundle::{BundleReader, ResolvedPath};

/// Validate that a filename from the bundle is safe to extract.
///
/// Rejects names that contain path separators, `..` components, or are
/// absolute paths — any of which could escape the output directory.
fn validate_extract_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("empty filename in bundle");
    }
    if name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || Path::new(name).is_absolute()
    {
        bail!("unsafe filename in bundle (path traversal attempt): {name:?}");
    }
    Ok(())
}

/// After joining a name onto `output_dir`, verify the canonical result still
/// lives under the canonical `output_dir`.
fn validate_output_path(output_dir: &Path, joined: &Path) -> Result<()> {
    let canonical_dir = output_dir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize output dir {}", output_dir.display()))?;
    let canonical_out = joined
        .canonicalize()
        .with_context(|| format!("failed to canonicalize output path {}", joined.display()))?;
    if !canonical_out.starts_with(&canonical_dir) {
        bail!(
            "path traversal: {} escapes output dir {}",
            canonical_out.display(),
            canonical_dir.display()
        );
    }
    Ok(())
}

/// `cjlb-view info` — print bundle metadata.
///
/// # Errors
///
/// Returns an error if the manifest header cannot be formatted.
#[allow(clippy::cast_precision_loss)] // display-only MiB conversion; precision loss is acceptable
pub fn cmd_info(reader: &BundleReader) -> Result<()> {
    println!("=== CJLB Bundle Info ===");
    println!("Version:        {}", reader.preamble_version);
    println!("Deployment TS:  {}", reader.deployment_ts);
    println!("Directories:    {}", reader.dir_count());
    println!("Files:          {}", reader.file_count());
    println!();

    if !reader.manifest_header.is_null() {
        println!("Manifest header:");
        let pretty = serde_json::to_string_pretty(&reader.manifest_header)
            .context("failed to format manifest header")?;
        println!("{pretty}");
    }

    // Compute total size by summing all file sizes
    let files = reader.files();
    let total_size: u64 = files
        .iter()
        .map(cjlb_format::route_table::FileRecord::file_size)
        .sum();
    println!();
    println!(
        "Total file size: {} bytes ({:.2} MiB)",
        total_size,
        total_size as f64 / (1024.0 * 1024.0)
    );

    Ok(())
}

/// `cjlb-view ls [path]` — list directory contents.
///
/// # Errors
///
/// Returns an error if the path cannot be resolved in the bundle.
pub fn cmd_ls(reader: &BundleReader, path: &str) -> Result<()> {
    let resolved = reader.resolve_path(path)?;
    match resolved {
        ResolvedPath::Dir(dir_idx) => {
            let dir = reader.dir_entry(dir_idx);
            let (child_dirs, child_files) = reader.dir_children(dir);

            for child_dir in child_dirs {
                let name = reader.dir_name(child_dir)?;
                println!("{name}/");
            }

            for child_file in child_files {
                let name = reader.file_name(child_file, dir)?;
                let size = child_file.file_size();
                println!("{name:<40} {size:>12} bytes");
            }
        }
        ResolvedPath::File { dir_idx, file_idx } => {
            let dir = reader.dir_entry(dir_idx);
            let file = &reader.files()[file_idx];
            let name = reader.file_name(file, dir)?;
            let size = file.file_size();
            println!("{name:<40} {size:>12} bytes");
        }
    }

    Ok(())
}

/// `cjlb-view cat <path>` — print file contents to stdout.
///
/// # Errors
///
/// Returns an error if the path is not a file, cannot be read, or writing to
/// stdout fails.
pub fn cmd_cat(reader: &BundleReader, path: &str) -> Result<()> {
    let resolved = reader.resolve_path(path)?;
    match resolved {
        ResolvedPath::File { file_idx, .. } => {
            let file = &reader.files()[file_idx];
            let data = reader.read_file(file)?;
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(&data)
                .context("failed to write to stdout")?;
        }
        ResolvedPath::Dir(_) => {
            bail!("'{path}' is a directory, not a file");
        }
    }

    Ok(())
}

/// `cjlb-view extract <path> <output_dir>` — extract file or directory.
///
/// # Errors
///
/// Returns an error if the path cannot be resolved, file data cannot be read,
/// filenames fail validation, or writing to the output directory fails.
pub fn cmd_extract(reader: &BundleReader, path: &str, output_dir: &Path) -> Result<()> {
    let resolved = reader.resolve_path(path)?;
    match resolved {
        ResolvedPath::File { dir_idx, file_idx } => {
            let dir = reader.dir_entry(dir_idx);
            let file = &reader.files()[file_idx];
            let name = reader.file_name(file, dir)?;
            validate_extract_name(name)?;
            let data = reader.read_file(file)?;

            fs::create_dir_all(output_dir)
                .with_context(|| format!("failed to create output dir {}", output_dir.display()))?;

            let out_path = output_dir.join(name);
            fs::write(&out_path, &data)
                .with_context(|| format!("failed to write {}", out_path.display()))?;

            validate_output_path(output_dir, &out_path)?;

            log::info!("extracted: {}", out_path.display());
        }
        ResolvedPath::Dir(dir_idx) => {
            extract_dir_recursive(reader, dir_idx, output_dir)?;
        }
    }

    Ok(())
}

/// Recursively extract a directory and all its contents.
fn extract_dir_recursive(reader: &BundleReader, dir_idx: usize, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create dir {}", output_dir.display()))?;

    let dir = reader.dir_entry(dir_idx);
    let (child_dirs, child_files) = reader.dir_children(dir);

    // Extract files in this directory
    for child_file in child_files {
        let name = reader.file_name(child_file, dir)?;
        validate_extract_name(name)?;
        let data = reader.read_file(child_file)?;
        let out_path = output_dir.join(name);
        fs::write(&out_path, &data)
            .with_context(|| format!("failed to write {}", out_path.display()))?;

        validate_output_path(output_dir, &out_path)?;

        log::info!("extracted: {}", out_path.display());
    }

    // Recurse into child directories
    for (j, child_dir) in child_dirs.iter().enumerate() {
        let child_name = reader.dir_name(child_dir)?;
        validate_extract_name(child_name)?;
        let child_dir_idx = dir.first_child_dir as usize + j;
        let child_out = output_dir.join(child_name);
        extract_dir_recursive(reader, child_dir_idx, &child_out)?;
    }

    Ok(())
}
