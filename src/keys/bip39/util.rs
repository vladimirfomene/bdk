pub const MIN_NUM_BITS: usize = 128;
pub const MAX_NUM_BITS: usize = 256;
pub const ENTROPY_MULTIPLE: usize = 32;
pub const WORD_BITS: usize = 11;
pub const BYTE_SIZE: usize = 8;
pub const PBKDF2_ITERATIONS: usize = 2048;
pub const PBKDF2_BYTES: usize = 64;
pub const WORDLIST_SIZE: usize = 2048;
pub const SALT_PREFIX: &'static str = "mnemonic";
pub const MAX_WORD_COUNT: usize = 24;
pub const MIN_WORD_COUNT: usize  = 12;


pub fn get_index_bit(byte: u8, index: usize) -> bool {
    let mask = 1 << (BYTE_SIZE - 1 - index);
    return byte & mask > 0
}


pub fn bits_to_usize(chunk: &[bool], size: usize) -> usize{
    let int: u32 = chunk
    .iter()
    .enumerate()
    .map(|(i, bit)| if *bit { 1 << (size - 1 - i) } else { 0 })
    .sum();

    return int as usize;
}


pub enum Error {
    OutOfBoundBitCount(usize),
    NotMultipleOf32(usize),
    BadWordCount(usize),
    WordNotFound
}