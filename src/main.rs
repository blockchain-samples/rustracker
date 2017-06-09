extern crate crypto;
extern crate regex;
extern crate rand;
extern crate time;
use time::PreciseTime;
use regex::Regex;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::io;

/// This is a simple block with `string` only payload
/// This block will be mined to receive a hash and points to its precedent
#[derive(Clone)]
struct Block {
    master: String,
    owner: String,
    previous: String,
    payload: String,
    nounce: u64,
    hash: String,
}

/// Simple self implemented u64 random iterator
struct Randoner {
    value: u64
}
/// Basic constructor implementation starting value with 0
impl Randoner {
    fn  new() -> Randoner {
        Randoner { value: 0 }
    }
}
/// Iterator implementation for Randoner, with rand::random
impl Iterator for Randoner {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        self.value = rand::random::<u64>();
        Some(self.value)
    }
}

/// Rules to have an accetable hash for mined proccess
#[derive(Clone)]
struct Rules {
    zeros: u32,
    max_nounce: u64,
}

/// Util function to get hash of a string
fn get_hash(data: &String) -> String {
    let mut sha = Sha256::new();
    sha.input_str(data);
    sha.result_str().to_string()
}

/// Mining function that generates a hash for some block, based in its properties
fn hashit<'a>(block: &'a mut Block, rules: &'a Rules) -> &'a Block {
    let rule = format!("^0{{{}}}", rules.zeros);
    let re = Regex::new(&rule).unwrap();
    let mut rnd = Randoner::new();

    loop {
        let nounce = rnd.next().unwrap();

        if nounce < rules.max_nounce {
            continue
        }

        block.nounce = nounce;
        let hashable = format!("{}{}{}{}{}", block.master, block.owner, block.previous, block.payload, block.nounce);
        let hash = get_hash(&hashable);
        if re.is_match(&hash) {
            block.hash = hash;
            break;
        }
    }

    block
}

fn main() {
    let rules = Rules {
        zeros: 5,
        max_nounce: 600000000u64,
    };

    println!("Digite o conteúdo para ser inserido no bloco:");
    let mut input = String::new();
    let content = match io::stdin().read_line(&mut input) {
        Ok(_) => input,
        Err(_) => "".to_string(),
    };

    let block = Block {
        master: "0".to_string(),
        owner: "1".to_string(),
        previous: "0".to_string(),
        payload: content.to_string(),
        nounce: 0,
        hash: "none".to_string()
    };
    let mut block_clone = block.clone();

    println!("Gerando o hash para o bloco...");
    let start = PreciseTime::now();
    let minted = hashit(&mut block_clone, &rules);
    let end = PreciseTime::now();

    println!("Block hash: {} nounce:{} in {}s", minted.hash, minted.nounce, start.to(end));
}
