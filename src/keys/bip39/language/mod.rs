mod english;

#[derive(Debug)]
pub enum Language {
    English
}

impl Language {


    pub fn word_list(&self) -> &'static [&'static str; 2048]{
        match self {
            Language::English => &english::WORDS
        }
    }

    pub fn get_word_index(&self, word: &str) -> Option<u16>{
        self.word_list().iter().position(|curr| *curr == word ).map(|i| i as u16);
    }
}