use anyhow::Result;
use sha2;
use whirlpool;
use hex;
use pkcs12::kdf::{Pkcs12KeyType, derive_key};

#[cxx::bridge(namespace = "pkcs12")]
mod ffi {
    unsafe extern "C++" {
        include!("pkcs12_kdf/include/pkcs12.hpp");

        fn pkcs12_key_gen(pass: &str, salt: &[u8], id: i32, iter: i32, keylen: usize, algo: i32) -> Result<Vec<u8>>; 
    }
}

fn main() -> Result<()> {
    let pass = "ge@äheim";
    let salt = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
    let iter = 100;

    let keylen = 32;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 2, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Iv, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 3, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Mac, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 20;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);
    
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 2, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Iv, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 3, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Mac, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);
 
    let keylen = 12;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);
    
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 2, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Iv, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 3, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Mac, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 32;
    let iter = 1000;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 2, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Iv, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 3, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::Mac, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 100;
    let iter = 1000;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 200;
    let iter = 1000;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 1)?;
    let key_cry = derive_key::<sha2::Sha256>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 32;
    let iter = 100;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 2)?;
    let key_cry = derive_key::<sha2::Sha512>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    let keylen = 32;
    let key_ssl = ffi::pkcs12_key_gen(pass, &salt, 1, iter, keylen, 3)?;
    let key_cry = derive_key::<whirlpool::Whirlpool>(pass, &salt, Pkcs12KeyType::EncryptionKey, iter, keylen);
    println!("Generated key: {}", hex::encode(&key_ssl));
    assert_eq!(key_ssl, key_cry);

    Ok(())
}


