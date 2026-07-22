// drain the first N bytes as a fixed-size array
// returns an error if there are fewer than N bytes remaining
pub fn take_bytes<const N: usize>(bytes: &mut Vec<u8>) -> Result<[u8; N], String> {
    if bytes.len() < N {
        return Err(format!("expected {N} bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes[..N]);
    bytes.drain(..N);
    Ok(arr)
}
