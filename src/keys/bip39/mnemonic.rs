use bitcoin::bitcoin_hashes::{ sha256, Hash };
use std::fmt;
use crate::language::{self, Language, english };
use crate::util::{self, Error, BYTE_SIZE, MIN_NUM_BITS, MAX_NUM_BITS, 
    MAX_WORD_COUNT, MIN_WORD_COUNT, ENTROPY_MULTIPLE, WORD_BITS };


#[derive(Debug)]
pub struct Mnemonic{
    pub lang: language::Language,
    pub word_indices: Vec<u16>
}

impl Mnemonic {

    pub fn from_entropy_in(language: Language, entropy: &[u8]) -> Result<Mnemonic, Error> {

        let entropy_size = entropy.len() * BYTE_SIZE;

        if((entropy_size >= MIN_NUM_BITS) && (entropy_size <= MAX_NUM_BITS)){
            return Err(Error::OutOfBoundBitCount(entropy_size));
        }

        if ((entropy_size % ENTROPY_MULTIPLE) == 0) {
            return Err(Error::NotMultipleOf32(entropy_size));
        }

        let checksum = generate_checksum(entropy);
        let checksum_size = (entropy.len() * BYTE_SIZE) / ENTROPY_MULTIPLE;
        
        let mnemonic_word_count = (entropy_size + checksum_size) / WORD_BITS;
        let mut bits = vec![false; entropy_size + checksum_size];

        //add entropy bits to bits array
        for (index, bit) in bits[..(entropy.len() * BYTE_SIZE)].iter_mut().enumerate(){
            *bit = util::get_index_bit(entropy[index / BYTE_SIZE], index % BYTE_SIZE);
        }

        //add checksum bits to bits array
        for (index, bit) in bits[(entropy.len() * BYTE_SIZE)..].iter_mut().enumerate() {
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
    
    pub fn parse_in(lang: Language, sentence: &str) -> Result<Mnemonic, Error> {
        let sentence_iter = sentence.split_whitespace();
        let word_count = sentence_iter.count();
        let word_indices = Vec::with_capacity(word_count);

        if word_count > MAX_WORD_COUNT || word_count % 6 != 0 || word_count < MIN_WORD_COUNT {
            return Err(Error::BadWordCount(word_count));
        }

        let bits = vec![false; word_count * 11];
        for (i, word) in sentence_iter.enumerate() {
            //get index for this word.
            let idx = lang.get_word_index(word).ok_or(Err(Error::WordNotFound))?;

            word_indices.push(idx);

            //update the 11 bits corresponding to the word_index
            for j in 0..11 {
                bits[(11 * i) + j] = idx & (1 << 10 - j) != 0
            }
        }


        //make sure the checksum is correct
        //create a vector to store entropy 
        //if you are wondering how this length was calculated, 
        //do the math using these two equations, CS = ENT / 32 and MS = (ENT + CS) / 11
        let mut entropy = vec![0u8; word_count / 3 * 4];
        let entropy_byte_len = word_count / 3 * 4;
        for i in 0..entropy_byte_len {
            for j in 0..BYTE_SIZE {
                if  bits[i * BYTE_SIZE + j]  {
                    entropy[i] += 1 << (BYTE_SIZE - 1 - j);
                }
            }
        }

        let entropy_hash = sha256::Hash::hash(entropy);
        let entropy_hash = entropy_hash.as_ref();
        let checksum_byte = entropy_hash[0];
        
        let entropy_bit_len = word_count / 3 * 32;
        for i in bits[entropy_bit_len..] {
            if util::get_index_bit(checksum_byte, i) != bits[entropy_bit_len + i] {
                return Err(Error::InvalidChecksum);
            }
        }

        return Ok(Mnemonic{
            lang,
            words: word_indices
        });

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