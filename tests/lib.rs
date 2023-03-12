use mysql_crypt::SqlCrypt;

const MONTY: &[u8] = b"monty";

#[test]
fn decode_100000_monty() {
    let x = vec![b'a'; 100_000];
    let y = mysql_crypt::encode(&x, MONTY);
    assert_ne!(x, y);
    assert_eq!(mysql_crypt::decode(&y, MONTY), x);
}

#[test]
fn decode_abcdef_monty() {
    let x = b"abcdef".to_vec();
    let y = mysql_crypt::encode(&x, MONTY);
    assert_eq!(y, b"\x99\xf7\x51\xcd\xf0\x8b");
    assert_eq!(mysql_crypt::decode(&y, MONTY), x);
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
