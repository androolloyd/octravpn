use rand::{CryptoRng, RngCore};
// Compact deterministic public fixture stream, never production entropy.
pub(crate) struct Entropy {
    state: u64,
    word: u64,
    available: usize,
    pub consumed: usize,
    pub calls: usize,
}
impl Entropy {
    pub(crate) fn new(state: u64) -> Self {
        Self {
            state,
            word: 0,
            available: 0,
            consumed: 0,
            calls: 0,
        }
    }
}
impl RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        self.try_fill_bytes(bytes).unwrap();
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.calls += 1;
        self.consumed += bytes.len();
        for byte in bytes {
            if self.available == 0 {
                self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = self.state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                self.word = z ^ (z >> 31);
                self.available = 8;
            }
            *byte = self.word as u8;
            self.word >>= 8;
            self.available -= 1;
        }
        Ok(())
    }
}
impl CryptoRng for Entropy {}
