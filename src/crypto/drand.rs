use std::fmt::Debug;

use rand_core::{RngCore, SeedableRng};
use rand_pcg::Pcg32;

use crate::crypto::Hash;

#[derive(Debug)]
pub struct SeedSource {
    /// Nerwork name
    pub nw_name: Vec<u8>,
    /// Nonce (8 Bytes)
    pub nonce: Vec<u8>,
    /// Db hash
    pub db: Hash,
    /// Previous seed
    pub previous_seed: u64,
}

impl SeedSource {
    /// It collects the node and network data to setup the initial seed
    // TODO: for now db is hash, check other approaches
    pub fn new(nw_name: Hash, nonce: Vec<u8>, db: Hash) -> Self {
        SeedSource {
            nw_name: nw_name.to_bytes(),
            nonce,
            db,
            previous_seed: 0,
        }
    }

    /// It returns the seed based on the structure sources
    pub fn get_seed(&self) -> u64 {
        // generate a Vec<u8> for each attribute of lenght
        // of the biggest between them
        let size = vec![
            self.nw_name.len(),
            self.nonce.len(),
            self.db.to_bytes().len(),
        ];
        let size = size.iter().max().unwrap(); // unwrap beacause it's secure to assume that the vector is not empty

        let mut nw_name: Vec<u8> = vec![0; *size];
        let mut nonce: Vec<u8> = vec![0; *size];
        let mut db: Vec<u8> = vec![0; *size];

        nw_name[..self.nw_name.len()].copy_from_slice(self.nw_name.as_slice());
        nonce[..self.nonce.len()].copy_from_slice(self.nonce.as_slice());
        db[..self.db.to_bytes().len()].copy_from_slice(self.db.as_bytes());

        // do xor between arrays
        let xor_result: Vec<u8> = nw_name
            .iter()
            .zip(nonce.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        let mut xor_result: Vec<u8> = xor_result
            .iter()
            .zip(db.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        // calcualte how many u64 are present in xor_result
        let reminder_of_u64 = xor_result.len() % std::mem::size_of::<u64>();
        // if rest is present do padding to have last u64
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
            .zip(self.previous_seed.to_be_bytes().iter())
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
    seed: SeedSource,
}

impl Drand {
    pub fn new(seed: SeedSource) -> Self {
        Drand {
            drng: Pcg32::seed_from_u64(seed.get_seed()),
            seed,
        }
    }

    fn update_seed(&mut self, seed: u64) {
        self.seed.previous_seed = seed;
        // TODO: update db hash
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

mod test {
    use super::*;
    use crate::crypto::hash::Hash;

    #[test]
    fn test_drand_sparsity() {
        let nw_name =
            Hash::from_hex("12202c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f22a5e886266e7ae")
                .unwrap();

        let nonce: Vec<u8> = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56];

        let db =
            Hash::from_hex("1220a4cea0f0f6eddc6865fd6092a319ccc6d2387cd8bb65e64bdc486f1a9a998569")
                .unwrap();

        let seed = SeedSource::new(nw_name, nonce, db);

        let mut drand = Drand::new(seed);
        let mut vec = vec![0; 10];

        for _ in 0..50000 {
            let rand = drand.rand(9);
            //println!("{}", rand);
            //println!("seed: {:?}", drand.seed);
            vec[(rand % 10) as usize] += 1;
        }

        println!("{:?}", vec);
    }
}
