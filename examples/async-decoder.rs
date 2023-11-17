use async_std::io::{BufReader, BufWriter, Read, ReadExt, Write};
use async_std::os::unix::net::UnixListener;
use async_std::stream::StreamExt;
use lazy_static::lazy_static;
use lru::LruCache;
use mysql_crypt::SqlCrypt;
use std::io::{ErrorKind, Result};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

#[cfg(all(unix, not(target_os = "macos")))]
use libsystemd::activation;

lazy_static! {
    static ref CACHE: Arc<Mutex<LruCache<Vec<u8>, SqlCrypt>>> =
        Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(16).unwrap())));
}

#[async_std::main]
async fn main() -> Result<()> {
    let p = "cryptd.sock";
    match std::fs::remove_file(p) {
        Ok(_) => {}
        Err(ref err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err);
        }
    }
    let listener = UnixListener::bind(p).await?;
    let mut incoming = listener.incoming();
    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => match handle(stream).await {
                Ok(_) => {}
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {}
                Err(err) => eprintln!("error: {:?}", err),
            },
            Err(err) => eprintln!("error: {:?}", err),
        }
    }
    std::fs::remove_file(p)?;
    Ok(())
}

async fn handle<RW>(stream: RW) -> Result<()>
where
    RW: Read + Write + Clone + Unpin,
{
    let mut r = BufReader::new(stream.clone());
    let key = read_sized_bytes(&mut r).await?;
    let mut x = {
        let cache = CACHE.clone();
        let mut cache = cache.lock().unwrap();
        cache
            .get_or_insert(key.clone(), || SqlCrypt::from_key(&key))
            .clone()
    };
    let mut w = x.new_decoder(BufWriter::new(stream));
    async_std::io::copy(&mut r, &mut w).await?;
    Ok(())
}

async fn read_sized_bytes<R>(mut r: R) -> Result<Vec<u8>>
where
    R: async_std::io::Read + Unpin,
{
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf).await?;
    let sz = u16::from_be_bytes(buf) as usize;
    let mut buf = vec![0u8; sz];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
