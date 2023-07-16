fn main() {
    cxx_build::bridge("src/main.rs")
        .file("src/pkcs12.cpp")
        .compile("cxxbridge-pkcs12_kdf");

    println!("cargo:rerun-if-changed=src/main.rs");
    println!("cargo:rerun-if-changed=src/pkcs12.cpp");
    println!("cargo:rerun-if-changed=include/pkcs12.hpp");
    println!("cargo:rustc-link-lib=dylib=crypto");
}

