use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

/// Maximum size of any simulator control, replay, corpus, or evidence input file.
pub(crate) const MAX_SIMULATOR_INPUT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn read_file(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    read_file_with_limit(path.as_ref(), MAX_SIMULATOR_INPUT_BYTES)
}

fn read_file_with_limit(path: &Path, maximum: usize) -> io::Result<Vec<u8>> {
    let read_limit = u64::try_from(maximum)
        .ok()
        .and_then(|maximum| maximum.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file limit is too large"))?;
    let file = File::open(path)?;
    let capacity = usize::try_from(file.metadata()?.len().min(read_limit)).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "file length does not fit usize")
    })?;
    let mut reader = file.take(read_limit);
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "simulator input file {} exceeds {maximum} bytes",
                path.display()
            ),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn read_file_rejects_the_first_byte_over_the_limit() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary input file");
        file.write_all(b"12345").expect("write test input");

        let error =
            read_file_with_limit(file.path(), 4).expect_err("the fifth byte must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds 4 bytes"));
    }

    #[test]
    fn read_file_accepts_the_exact_limit() {
        let mut file = tempfile::NamedTempFile::new().expect("temporary input file");
        file.write_all(b"1234").expect("write test input");

        assert_eq!(
            read_file_with_limit(file.path(), 4).expect("exact limit must be accepted"),
            b"1234"
        );
    }
}
