use std::fmt;
use std::fmt::{Formatter, Error};
use rand::RngCore;
use rand::rngs::OsRng;
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;

pub struct LamportSignature (Vec<[u8; 32]>);

pub struct LamportPrivateKey {
    key: Vec<([u8; 32], [u8; 32])>
}

impl LamportPrivateKey {
    pub fn new() -> Self {
        let mut priv_key = LamportPrivateKey {
            key: Vec::new(),
        };

        for _ in 0..256 {
            let (mut p0, mut p1) = ([0u8; 32], [0u8; 32]);
            OsRng.fill_bytes(&mut p0);
            OsRng.fill_bytes(&mut p1);
            priv_key.key.push((p0, p1));
        }

        priv_key
    }

    pub fn sign(&self, msg: &[u8]) -> LamportSignature {
        let hashed_msg = sha256::Hash::hash(msg).into_inner();
        let mut signature = Vec::new();

        for byte in hashed_msg.iter() {
            for i in 0..8 {
                if get_bit(*byte, i).unwrap() {
                    signature.push(self.key[i as usize].1);
                } else {
                    signature.push(self.key[i as usize].0);
                }
            }
        }

        LamportSignature(signature)
    }
}

impl fmt::Display for LamportPrivateKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "private0: ");
        for (i, _) in self.key.iter() {
            for byte in i.iter() {
                write!(f, "{:02x}", byte)?;
            }
        }

        write!(f, "\nprivate1: ");
        for (_, i) in self.key.iter() {
            for byte in i.iter() {
                write!(f, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

pub struct LamportPublicKey {
    key: Vec<([u8; 32], [u8; 32])>
}

impl LamportPublicKey {
    pub fn new(priv_key: &LamportPrivateKey) -> Self {
        let mut public_key = LamportPublicKey {
            key: Vec::new(),
        };

        for (ref i, ref j) in priv_key.key.iter() {
            let hash_priv0 = sha256::Hash::hash(i);
            let hash_priv1 = sha256::Hash::hash(j);
            public_key.key.push((hash_priv0.into_inner(), hash_priv1.into_inner()))
        }

        public_key
    }

    pub fn verify(&self, msg: &[u8], signature: &LamportSignature) -> bool {
        let hashed_msg = sha256::Hash::hash(msg).into_inner();
        let mut signature_pub = Vec::new();

        for byte in hashed_msg.iter() {
            for i in 0..8 {
                if get_bit(*byte, i).unwrap() {
                    signature_pub.push(self.key[i as usize].1);
                } else {
                    signature_pub.push(self.key[i as usize].0);
                }
            }
        }

        let count = signature_pub.iter().zip(&signature.0)
            .filter(|&(i, j)| i == &sha256::Hash::hash(j).into_inner())
            .count();
        count == 256
    }
}

impl fmt::Display for LamportPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "public0: ");
        for (i, _) in self.key.iter() {
            for byte in i.iter() {
                write!(f, "{:02x}", byte)?;
            }
        }

        write!(f, "\npublic1: ");
        for (_, i) in self.key.iter() {
            for byte in i.iter() {
                write!(f, "{:02x}", byte)?;
            }
        }

        Ok(())
    }
}

pub fn generate_keypair() -> LamportPrivateKey {
    LamportPrivateKey::new()
}

pub fn sign() {}

pub fn verify() {}

fn get_bit(byte: u8, index: u8) -> Result<bool, ()> {
    if index < 8 {
        Ok(byte & (1 << index) != 0)
    } else {
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{LamportPrivateKey, LamportPublicKey, sign};

    #[test]
    fn verify_works() {
        let priv_key = LamportPrivateKey::new();
        let pub_key = LamportPublicKey::new(&priv_key);

        let msg = "lamport".as_bytes();

        let signature = priv_key.sign(msg);

        let success = pub_key.verify(msg, &signature);

        assert!(success);
    }
}
