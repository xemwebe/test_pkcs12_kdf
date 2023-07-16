#include "pkcs12_kdf/include/pkcs12.hpp"
#include "pkcs12_kdf/src/main.rs.h"
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <vector>
#include <limits>

auto conv_cvec_to_vecu8(const std::vector<unsigned char> &bytes) -> rust::Vec<rust::u8> {
    rust::Vec<rust::u8> retbytes;
    retbytes.reserve(bytes.size());
    std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(retbytes));
    return retbytes;
}

namespace pkcs12 {

    rust::Vec<rust::u8> pkcs12_key_gen(
        rust::Str pass,
        rust::Slice<const rust::u8> salt,
        int id,
        int iter,
        long unsigned int keylen,
        int algo
    ) {
        int max_int = std::numeric_limits<int>::max();
        if(pass.size()>static_cast<size_t>(max_int)
        || salt.size()>static_cast<size_t>(max_int)
        || keylen == 0) {
            throw std::runtime_error("key gen failed: value out of bound");
        }
        std::vector<unsigned char> out(keylen);
        
        int result = -99;
        if (algo==1) {
            result = PKCS12_key_gen_utf8(
                pass.data(), pass.size(),
                (unsigned char *)(salt.data()), salt.size(),
                id, iter, keylen, out.data(), EVP_sha256());
        } else if(algo==2) {
            result = PKCS12_key_gen_utf8(
                pass.data(), pass.size(),
                (unsigned char *)(salt.data()), salt.size(),
                id, iter, keylen, out.data(), EVP_sha512());
        } else if(algo==3) {
            result = PKCS12_key_gen_utf8(
                pass.data(), pass.size(),
                (unsigned char *)(salt.data()), salt.size(),
                id, iter, keylen, out.data(), EVP_whirlpool());
        }
        if (result==-99) {
            throw std::runtime_error("unsupported algorithm");
        }
        if(result==0) {
            throw std::runtime_error("key gen failed, call to openssl returns with error");
        }
        return conv_cvec_to_vecu8(out);
  }

}
