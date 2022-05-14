use bitcoin::bitcoin_hashes::{ sha256, Hash };
use std::fmt;
use crate::language::{self, Language, english };
use crate::util::{self, Error};


#[derive(Debug)]
pub struct Mnemonic{
    pub lang: language::Language,
    pub word_indices: Vec<u16>
}

impl Mnemonic {

    pub fn from_entropy_in(language: Language, entropy: &[u8]) -> Result<Mnemonic, Error> {

        let entropy_size = entropy.len() * util::BYTE_SIZE;

        if((entropy_size >= MIN_NUM_BITS) && (entropy_size <= MAX_NUM_BITS)){
            return Err(Error::OutOfBoundBitCount(entropy_size));
        }

        if ((entropy_size % ENTROPY_MULTIPLE) == 0) {
            return Err(Error::NotMultipleOf32(entropy_size));
        }

        let checksum = generate_checksum(entropy);
        let checksum_size = (entropy.len() * util::BYTE_SIZE) / util::ENTROPY_MULTIPLE;
        
        let mnemonic_word_count = (entropy_size + checksum_size) / util::WORD_BITS;
        let mut bits = vec![false; entropy_size + checksum_size];

        //add entropy bits to bits array
        for (index, bit) in bits[..(entropy.len() * util::BYTE_SIZE)].iter_mut().enumerate(){
            *bit = util::get_index_bit(entropy[index / util::BYTE_SIZE], index % util::BYTE_SIZE);
        }

        //add checksum bits to bits array
        for (index, bit) in bits[(entropy.len() * util::BYTE_SIZE)..].iter_mut().enumerate() {
            *bit = util::get_index_bit(checksum[0], index);
        }

        //create vector to store mnemonic words
        let mut mnemonic_indices = Vec::with_capacity(mnemonic_word_count);
        for chunk in bits[..(checksum_size + entropy_size)].chunks(11) {
            //convert 11 bit chunk to word index
            let word_index = util::bits_to_usize(chunk, 11);

            //add word index to word index list
            mnemonic_words.push(word_index);
        }

        //return Mnemonic
        return Ok(Mnemonic {
            lang: language,
            words: mnemonic_indices
        });
        
    }


    ///Generate seed of a mnemonic from the passphrase
    pub fn to_seed(&self, passphrase: &str) -> [u8; util::PBKDF2_BYTES] {
        let mnemonic_sentence = self.generate_mnemonic_words().join(" ");
        let normalized_mnemonic = mnemonic_sentence.nfkd().collect::<String>();
        let normalized_mnemonic = normalized_mnemonic.as_bytes();
        let salt = format!("{}{}", util::SALT_PREFIX, passphrase);
        let normalized_salt = salt.nfkd().collect::<String>();
        let normalized_salt = normalized_salt.as_bytes();
        let mut seed = [0u8; PBKDF2_BYTES];
        pbkdf2::pbkdf2(normalized_mnemonic, normalized_salt, PBKDF2_ITERATIONS as usize, &mut seed);
        return seed;
    }
    


    fn generate_mnemonic_words(&self) -> Vec<&'static str> {
        let word_list = self.lang.word_list();
        let mnemonic_words = self.word_indices.iter().map(|idx| word_list[idx]).collect::<&'static str>();
        return mnemonic_words;
    }

    fn generate_checksum(entropy: &[u8]) -> Vec<u8> {
        let entropy_hash = sha256::Hash::hash(entropy);
        let entropy_hash = entropy_hash.as_ref();
    
        return entropy_hash[0..1].to_owned();
    }


}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let words = self.lang.word_list();
        for i in self.word_indices {
            if i > 0 {
                write!(f, " ");
            }
            write!(f, "{}", words[i]);
        }
        
    }
}