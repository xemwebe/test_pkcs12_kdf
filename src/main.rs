use anyhow::Result;
use sha2::{Digest, Sha256};
use hex;

#[cxx::bridge(namespace = "pkcs12")]
mod ffi {
    unsafe extern "C++" {
        include!("pkcs12_kdf/include/pkcs12.hpp");

        fn pkcs12_key_gen(pass: &str, salt: &[u8], id: i32, iter: i32, keylen: i32) -> Result<Vec<u8>>; 
    }
}

pub fn key_gen_utf8(
    pass: &str,
    salt: &[u8],
    id: i32,
    iter: i32,
    keylen: i32,
) -> Result<Vec<u8>> {
    Ok(ffi::pkcs12_key_gen(pass, salt, id, iter, keylen)?)
}

pub fn str_to_unicode(s: &str) -> Vec<u8> {
    let mut unicode: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_be_bytes().to_vec()).collect();
    unicode.push(0);
    unicode.push(0);
    unicode
}

pub fn key_gen_rs(
    pass: &str,
    salt: &[u8],
    id: i32,
    iter: i32,
    keylen: i32,
) -> Result<Vec<u8>> {
    println!("pass: {pass}");
    let pass_uni = str_to_unicode(pass);
    println!("pass in unicode: {}", hex::encode(pass_uni.clone()));
    let u = 32;
    let v = 64;
    let slen = v*((salt.len()+v-1)/v);
    let plen = v*((pass_uni.len() + v - 1)/v);
    let ilen = slen + plen;
    let mut i_tmp = vec![0u8; ilen];
    for i in 0..slen {
        i_tmp[i] = salt[i%salt.len()];
    }
    for i in slen..ilen {
        i_tmp[i] = pass_uni[(i-slen)%pass_uni.len()];
    }
    println!("I = {}", hex::encode(i_tmp.clone()));
    let mut hasher = Sha256::new();
    let d_tmp = vec![id as u8; v];
    hasher.update(&d_tmp);
    hasher.update(&i_tmp);
    let mut result = hasher.finalize();
    for i in 1..iter {
        let mut hasher = Sha256::new();
        hasher.update(&result[0..u]);
        result = hasher.finalize();
    }
    let m = (keylen as usize).min(u) as usize;
    Ok(result[0..m].to_vec())
}


fn main() -> Result<()> {
    let pass = "ge@äheim";
    let salt = [0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
    let id = 3;
    let iter = 100;
    let keylen = 40;
    let key1 = key_gen_utf8(pass, &salt, id, iter, keylen)?;
    let key2 = key_gen_rs(pass, &salt, id, iter, keylen)?;

    println!("Generated key1: {}", hex::encode(&key1));
    println!("Generated key2: {}", hex::encode(&key2));

    Ok(())
}


