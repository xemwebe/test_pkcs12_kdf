#pragma once
#include <rust/cxx.h>

namespace pkcs12 {
    rust::Vec<rust::u8> pkcs12_key_gen(
        rust::Str pass,
        rust::Slice<const rust::u8> salt,
        int id,
        int iter,
        int keylen
    );
}

