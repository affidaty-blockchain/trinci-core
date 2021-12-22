use std::fmt::Debug;

use merkledb::BinaryKey;
use rand_core::{RngCore, SeedableRng};
use rand_pcg::Pcg32;

use crate::crypto::Hash;

use super::HashAlgorithm;

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
        let db = self.db.as_bytes().to_vec();
        let nonce = Hash::new(HashAlgorithm::Sha256, self.nonce.as_slice())
            .unwrap()
            .as_bytes()
            .to_vec();
        let nw_name = Hash::new(HashAlgorithm::Sha256, self.nw_name.as_slice())
            .unwrap()
            .as_bytes()
            .to_vec();

        let mut sum: Vec<u8> = vec![0; db.size()];

        for j in 0..db.size() {
            sum[j] = db[j] + nonce[j] + nw_name[j];
        }

        let hash = Hash::from_bytes(sum.as_slice()).unwrap();

        let (res, _rest) = hash.as_bytes().split_at(std::mem::size_of::<u64>());
        u64::from_be_bytes(res.try_into().unwrap()) + self.previous_seed
    }

    //pub fn get_seed(&self) -> u64 {
    //    let (res, _rest) = self.nw_name.as_slice().split_at(std::mem::size_of::<u64>());
    //    let nw_name = u64::from_be_bytes(res.try_into().unwrap()) % u64::MAX;

    //    let (res, _rest) = self.nonce.as_slice().split_at(std::mem::size_of::<u64>());
    //    let nonce = u64::from_be_bytes(res.try_into().unwrap()) % u64::MAX;

    //    let (res, _rest) = self.db.as_bytes().split_at(std::mem::size_of::<u64>());
    //    let db = u64::from_be_bytes(res.try_into().unwrap()) % u64::MAX;

    //    let mut sum = nonce.saturating_add(db);
    //    sum = sum.saturating_add(self.previous_seed);
    //    sum.saturating_add(nw_name)
    //}
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

        rand_number % (max + 1)
    }
}

mod test {
    use super::Drand;
    use crate::crypto::drand::SeedSource;
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

        for _ in 0..5 {
            let rand = drand.rand(9);
            //println!("{}", rand);
            println!("seed: {:?}", drand.seed);
            vec[(rand % 10) as usize] += 1;
        }

        println!("{:?}", vec);
    }
}
