//! Fail-closed validation before redb opens an existing durable store.

use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    mem::size_of,
    path::Path,
};

use crate::IdentityError;

// redb 4.1's frozen on-disk super-header fields. The dependency is pinned by Cargo.lock. Keeping
// this small parser at the adapter boundary prevents redb's internal layout assertions from seeing
// crash-truncated files. A future redb layout must fail closed here until reviewed.
const REDB_MAGIC: [u8; 9] = [b'r', b'e', b'd', b'b', 0x1a, 0x0a, 0xa9, 0x0d, 0x0a];
const REDB_HEADER_BYTES: usize = 320;
const REDB_LAYOUT_PREFIX_BYTES: usize = 32;
const REDB_PAGE_SIZE: u64 = 4_096;
const PAGE_SIZE_OFFSET: usize = 12;
const REGION_HEADER_PAGES_OFFSET: usize = 16;
const REGION_MAX_DATA_PAGES_OFFSET: usize = 20;
const NUM_FULL_REGIONS_OFFSET: usize = 24;
const TRAILING_REGION_DATA_PAGES_OFFSET: usize = 28;

pub(crate) fn validate_existing_redb_file(path: &Path) -> Result<(), IdentityError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(IdentityError::StorageCorruption),
    };
    let actual_length = metadata.len();
    if !metadata.is_file()
        || actual_length < REDB_HEADER_BYTES as u64
        || actual_length % REDB_PAGE_SIZE != 0
    {
        return Err(IdentityError::StorageCorruption);
    }

    let mut prefix = [0_u8; REDB_LAYOUT_PREFIX_BYTES];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .map_err(|_| IdentityError::StorageCorruption)?;
    if prefix[..REDB_MAGIC.len()] != REDB_MAGIC {
        return Err(IdentityError::StorageCorruption);
    }

    let page_size = u64::from(read_u32(&prefix, PAGE_SIZE_OFFSET)?);
    let region_header_pages = u64::from(read_u32(&prefix, REGION_HEADER_PAGES_OFFSET)?);
    let region_max_data_pages = u64::from(read_u32(&prefix, REGION_MAX_DATA_PAGES_OFFSET)?);
    let full_regions = u64::from(read_u32(&prefix, NUM_FULL_REGIONS_OFFSET)?);
    let trailing_data_pages = u64::from(read_u32(&prefix, TRAILING_REGION_DATA_PAGES_OFFSET)?);
    if page_size != REDB_PAGE_SIZE
        || region_max_data_pages == 0
        || trailing_data_pages > region_max_data_pages
        || (full_regions == 0 && trailing_data_pages == 0)
    {
        return Err(IdentityError::StorageCorruption);
    }

    let full_region_pages = region_header_pages
        .checked_add(region_max_data_pages)
        .ok_or(IdentityError::StorageCorruption)?;
    let full_region_bytes = full_region_pages
        .checked_mul(page_size)
        .ok_or(IdentityError::StorageCorruption)?;
    let full_bytes = full_regions
        .checked_mul(full_region_bytes)
        .ok_or(IdentityError::StorageCorruption)?;
    let trailing_bytes = if trailing_data_pages == 0 {
        0
    } else {
        region_header_pages
            .checked_add(trailing_data_pages)
            .and_then(|pages| pages.checked_mul(page_size))
            .ok_or(IdentityError::StorageCorruption)?
    };
    let header_and_regions = page_size
        .checked_add(full_bytes)
        .and_then(|length| length.checked_add(trailing_bytes))
        .ok_or(IdentityError::StorageCorruption)?;
    if actual_length < header_and_regions {
        return Err(IdentityError::StorageCorruption);
    }
    Ok(())
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, IdentityError> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or(IdentityError::StorageCorruption)?;
    let encoded = bytes
        .get(offset..end)
        .ok_or(IdentityError::StorageCorruption)?;
    Ok(u32::from_le_bytes(
        encoded
            .try_into()
            .map_err(|_| IdentityError::StorageCorruption)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_creatable_but_existing_short_file_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.redb");
        assert_eq!(validate_existing_redb_file(&missing), Ok(()));

        let short = directory.path().join("short.redb");
        fs::write(&short, REDB_MAGIC).unwrap();
        assert_eq!(
            validate_existing_redb_file(&short),
            Err(IdentityError::StorageCorruption)
        );
    }
}
