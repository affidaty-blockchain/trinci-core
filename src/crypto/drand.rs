use std::fmt::Debug;
use std::sync::Arc;

use rand_core::{RngCore, SeedableRng};
use rand_pcg::Pcg32;

use crate::base::Mutex;
use crate::crypto::Hash;

#[derive(Debug)]
pub struct SeedSource {
    /// Network name
    pub nw_name: Vec<u8>,
    /// Nonce (8 Bytes)
    pub nonce: Mutex<Vec<u8>>,
    /// Database hashes
    pub prev_hash: Mutex<Hash>,
    pub txs_hash: Mutex<Hash>,
    pub rxs_hash: Mutex<Hash>,
    /// Previous seed
    pub previous_seed: Mutex<u64>,
}

impl SeedSource {
    /// It collects the node and network data to setup the initial seed
    pub fn new(
        nw_name: String,
        nonce: Vec<u8>,
        prev_hash: Hash,
        txs_hash: Hash,
        rxs_hash: Hash,
    ) -> Self {
        SeedSource {
            nw_name: nw_name.as_bytes().to_vec(),
            nonce: Mutex::new(nonce),
            prev_hash: Mutex::new(prev_hash),
            txs_hash: Mutex::new(txs_hash),
            rxs_hash: Mutex::new(rxs_hash),
            previous_seed: Mutex::new(0),
        }
    }

    /// It returns the seed based on the structure sources
    pub fn get_seed(&self) -> u64 {
        // generate a Vec<u8> for each attribute of length
        // of the biggest between them
        let size_vec: Vec<usize> = vec![
            self.nw_name.len(),
            self.nonce.lock().len(),
            self.prev_hash.lock().to_bytes().len(),
            self.txs_hash.lock().to_bytes().len(),
            self.rxs_hash.lock().to_bytes().len(),
        ];

        let size = size_vec.iter().max().unwrap(); // unwrap because it's secure to assume that the vector is not empty

        let mut nw_name: Vec<u8> = vec![0; *size];
        let mut nonce: Vec<u8> = vec![0; *size];
        let mut prev_hash: Vec<u8> = vec![0; *size];
        let mut txs_hash: Vec<u8> = vec![0; *size];
        let mut rxs_hash: Vec<u8> = vec![0; *size];

        // retrieve slices from mutex attributes
        nw_name[..size_vec[0]].copy_from_slice(self.nw_name.as_slice());
        nonce[..size_vec[1]].copy_from_slice(self.nonce.lock().as_slice());
        prev_hash[..size_vec[2]].copy_from_slice(self.prev_hash.lock().as_bytes());
        txs_hash[..size_vec[3]].copy_from_slice(self.txs_hash.lock().as_bytes());
        rxs_hash[..size_vec[4]].copy_from_slice(self.rxs_hash.lock().as_bytes());

        // do xor between arrays
        let xor_result: Vec<u8> = nw_name
            .iter()
            .zip(nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        let xor_result: Vec<u8> = xor_result
            .iter()
            .zip(prev_hash.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        let xor_result: Vec<u8> = xor_result
            .iter()
            .zip(txs_hash.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        let mut xor_result: Vec<u8> = xor_result
            .iter()
            .zip(rxs_hash.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        // Calculates how many u64 are present in xor_result
        let reminder_of_u64 = xor_result.len() % std::mem::size_of::<u64>();
        // if reminder is present do padding to have last u64
        if reminder_of_u64 > 0 {
            let mut reminder_vec: Vec<u8> = vec![0; std::mem::size_of::<u64>() - reminder_of_u64];
            xor_result.append(&mut reminder_vec);
        }

        // do xor chunkwise
        let mut vec_u64: Vec<u8> = vec![0; std::mem::size_of::<u64>()];
        for element in xor_result.as_slice().chunks(std::mem::size_of::<u64>()) {
            vec_u64 = vec_u64
                .iter()
                .zip(element.iter())
                .map(|(&x1, &x2)| x1 ^ x2)
                .collect();
        }

        let vec_u64: Vec<u8> = vec_u64
            .iter()
            .zip(self.previous_seed.lock().to_be_bytes().iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        u64::from_be_bytes(vec_u64.try_into().unwrap())
    }
}

#[derive(Debug)]
pub struct Drand {
    /// RNG
    drng: Pcg32,
    /// Seed's source
    seed: Arc<SeedSource>,
}

impl Drand {
    pub fn new(seed: Arc<SeedSource>) -> Self {
        Drand {
            drng: Pcg32::seed_from_u64(seed.get_seed()),
            seed,
        }
    }

    fn update_seed(&mut self, seed: u64) {
        let mut previous_seed = self.seed.previous_seed.lock();
        *previous_seed = seed;
    }

    /// returns a pseudo-random number between the range specified in the struct
    pub fn rand(&mut self, max: u64) -> u64 {
        // get pseudo-random number
        let rand_number = self.drng.next_u64();

        self.update_seed(rand_number);

        self.drng = Pcg32::seed_from_u64(self.seed.get_seed());
        //println!("rnd: {}", rand_number); // DEBUG
        rand_number % (max + 1)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::crypto::hash::Hash;

    #[test]
    fn test_drand_sparsity() {
        let nw_name = String::from("nw_name_test");

        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];

        let prev_hash =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();

        let txs_hash =
            Hash::from_hex("1220a4cea0f1f6eddc6865fd6092a319ccc6d2387cf8bb63e64b4c48601a9a998569")
                .unwrap();

        let rxs_hash =
            Hash::from_hex("1220a4cea0f0f6edd46865fd6092a319ccc6d5387cd8bb65e64bdc486f1a9a998569")
                .unwrap();

        let seed = SeedSource::new(nw_name, nonce, prev_hash, txs_hash, rxs_hash);

        let seed = Arc::new(seed);

        let mut drand = Drand::new(seed.clone());
        let mut vec = vec![0; 10];

        for _ in 0..10000 {
            let rand = drand.rand(9);
            //println!("{}", rand);
            //println!("seed: {:?}", drand.seed);
            vec[(rand % 10) as usize] += 1;
        }

        println!("{:?}", vec);
    }
}
