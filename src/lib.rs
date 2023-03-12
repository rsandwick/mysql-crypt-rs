pub fn decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    SqlCrypt::from_key(key).decode(data.to_vec())
}

pub fn encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    SqlCrypt::from_key(key).encode(data.to_vec())
}

const MY_RND_MAX: u64 = 0x3fffffff;
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
        let z: f64 = unsafe { std::mem::transmute(self.0) };
        z / MY_RND_MAXF
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
            self.shift ^= (self.rand.next() * 255.0) as usize;
            let j = (x[i] as usize) ^ self.shift;
            x[i] = self.dbuf[j];
            self.shift ^= x[i] as usize;
        }
    }

    pub fn encode(&mut self, x: Vec<u8>) -> Vec<u8> {
        let mut x = x.clone();
        self.encode_inplace(&mut x);
        x
    }

    pub fn encode_inplace(&mut self, x: &mut [u8]) {
        for i in 0..x.len() {
            self.shift ^= (self.rand.next() * 255.0) as usize;
            let j = x[i] as usize;
            x[i] = self.ebuf[j] ^ (self.shift as u8);
            self.shift ^= j;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{decode, encode, SqlCrypt};

    const MONTY: &[u8] = b"monty";

    #[test]
    fn decode_100000_monty() {
        let mut x: Vec<u8> = Vec::with_capacity(100000);
        x.resize(100000, b'a');
        let y = encode(&x, MONTY);
        assert_ne!(x, y);
        assert_eq!(decode(&y, MONTY), x);
    }

    #[test]
    fn decode_abcdef_monty() {
        let x = b"abcdef".to_vec();
        let y = encode(&x, MONTY);
        assert_eq!(y, b"\x99\xf7\x51\xcd\xf0\x8b");
        assert_eq!(decode(&y, MONTY), x);
    }

    #[test]
    fn use_after_reinit() {
        let mut c = SqlCrypt::from_key(MONTY);
        let x = b"abcdef".to_vec();
        let y = c.encode(x.clone());
        assert_ne!(c.decode(y.clone()), x);
        c.reinit();
        assert_eq!(c.decode(y), x);
    }
}
