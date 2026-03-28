#![no_main]
use libfuzzer_sys::fuzz_target;
use cjlb_format::route_table::*;

fuzz_target!(|data: &[u8]| {
    if data.len() < std::mem::size_of::<RouteTableHeader>() {
        return;
    }

    // Try parsing the header
    let header: &RouteTableHeader = match bytemuck::try_from_bytes(&data[..32]) {
        Ok(h) => h,
        Err(_) => return,
    };

    if header.magic != ROUTE_TABLE_MAGIC {
        return;
    }

    let dir_count = header.dir_count as usize;
    let file_count = header.file_count as usize;
    let span_count = header.span_count as usize;

    // Bounds check — use checked arithmetic to avoid overflow
    let dir_size = match dir_count.checked_mul(std::mem::size_of::<DirEntry>()) {
        Some(s) => s,
        None => return,
    };
    let file_size = match file_count.checked_mul(std::mem::size_of::<FileRecord>()) {
        Some(s) => s,
        None => return,
    };
    let span_size = match span_count.checked_mul(std::mem::size_of::<PageSpan>()) {
        Some(s) => s,
        None => return,
    };

    let total = match 32usize.checked_add(dir_size).and_then(|t| t.checked_add(file_size)).and_then(|t| t.checked_add(span_size)) {
        Some(t) => t,
        None => return,
    };
    if total > data.len() {
        return;
    }

    // Try casting to slices
    let dir_bytes = &data[32..32 + dir_size];
    let file_bytes = &data[32 + dir_size..32 + dir_size + file_size];
    let span_bytes = &data[32 + dir_size + file_size..32 + dir_size + file_size + span_size];

    let _dirs: &[DirEntry] = match bytemuck::try_cast_slice(dir_bytes) {
        Ok(d) => d,
        Err(_) => return,
    };
    let _files: &[FileRecord] = match bytemuck::try_cast_slice(file_bytes) {
        Ok(f) => f,
        Err(_) => return,
    };
    let _spans: &[PageSpan] = match bytemuck::try_cast_slice(span_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // If we got here, parsing succeeded -- no panic
});
