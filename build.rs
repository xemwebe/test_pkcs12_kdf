fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/pkcs12.cpp")
        .compile("cxxbridge-pkcs12_kdf");

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/pkcs12.cpp");
    println!("cargo:rerun-if-changed=include/pkcs12.hpp");
    println!("cargo:rerun-if-changed=/home/makr/src/openssl/libcrypto.a");
    println!("cargo:rustc-link-search=/home/mark/src/openssl");
    println!("cargo:rustc-link-lib=static=crypto");
}

