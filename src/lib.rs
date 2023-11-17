#[cfg(feature = "async")]
mod async_decode;

pub fn decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    SqlCrypt::from_key(key).decode(data.to_vec())
}

pub fn encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    SqlCrypt::from_key(key).encode(data.to_vec())
}

const MY_RND_MAX: u64 = 0x3fffffff;
// UNSAFE: f64::from_bits is currently const:unstable; use transmute for now
//         https://doc.rust-lang.org/std/primitive.f64.html#method.from_bits
const MY_RND_MAXF: f64 = unsafe { std::mem::transmute(MY_RND_MAX) };

#[derive(Clone, Copy)]
struct MyRnd(u64, u64);

impl MyRnd {
    fn from_key(key: &[u8]) -> Self {
        let mut x: u64 = 1345345333;
        let mut y: u64 = 0x12345671;
        let mut z: u64 = 7;
        for &k in key {
            if k == b' ' || k == b'\t' {
                continue;
            }
            x ^= (((x & 0x3f) + z) * (k as u64)) + (x << 8);
            y = y.wrapping_add((y << 8) ^ x);
            z = z.wrapping_add(k as u64);
        }
        Self(x & 0x7fffffff, y & 0x7fffffff)
    }

    #[inline(always)]
    fn next(&mut self) -> f64 {
        self.0 = ((self.0 * 3) + self.1) % MY_RND_MAX;
        self.1 = (self.0 + self.1 + 33) % MY_RND_MAX;
        f64::from_bits(self.0) / MY_RND_MAXF
    }
}

#[derive(Clone, Copy)]
pub struct SqlCrypt {
    dbuf: [u8; 256],
    ebuf: [u8; 256],
    org_rand: MyRnd,
    rand: MyRnd,
    shift: usize,
}

impl SqlCrypt {
    pub fn from_key(key: &[u8]) -> Self {
        Self::from_seed(MyRnd::from_key(key))
    }

    fn from_seed(x: MyRnd) -> Self {
        let mut x = x;
        let mut dbuf: [u8; 256] = core::array::from_fn(|i| i as u8);
        for i in 0..=255 {
            let j = (x.next() * 255.0) as usize;
            (dbuf[i], dbuf[j]) = (dbuf[j], dbuf[i]);
        }
        let mut ebuf: [u8; 256] = [0; 256];
        for (i, &v) in dbuf.iter().enumerate() {
            ebuf[v as usize] = i as u8;
        }
        SqlCrypt {
            dbuf: dbuf,
            ebuf: ebuf,
            org_rand: x.clone(),
            rand: x,
            shift: 0,
        }
    }

    pub fn reinit(&mut self) {
        self.rand = self.org_rand;
        self.shift = 0;
    }

    pub fn decode(&mut self, x: Vec<u8>) -> Vec<u8> {
        let mut x = x.clone();
        self.decode_inplace(&mut x);
        x
    }

    pub fn decode_inplace(&mut self, x: &mut [u8]) {
        for i in 0..x.len() {
            x[i] = self.decode_byte(x[i]);
        }
    }

    #[inline(always)]
    fn decode_byte(&mut self, x: u8) -> u8 {
        self.shift ^= (self.rand.next() * 255.0) as usize;
        let j = (x as usize) ^ self.shift;
        let y = self.dbuf[j];
        self.shift ^= y as usize;
        y
    }

    pub fn encode(&mut self, x: Vec<u8>) -> Vec<u8> {
        let mut x = x.clone();
        self.encode_inplace(&mut x);
        x
    }

    pub fn encode_inplace(&mut self, x: &mut [u8]) {
        for i in 0..x.len() {
            x[i] = self.encode_byte(x[i]);
        }
    }

    #[inline(always)]
    fn encode_byte(&mut self, x: u8) -> u8 {
        self.shift ^= (self.rand.next() * 255.0) as usize;
        let j = x as usize;
        let y = self.ebuf[j] ^ (self.shift as u8);
        self.shift ^= j;
        y
    }
}
