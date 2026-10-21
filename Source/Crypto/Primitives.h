#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace Pgp
{
    using Bytes = std::vector<uint8_t>;

    // every error we throw is one of these, the UI just prints .what() straight into the status line
    class Error : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    enum class HashAlgorithm
    {
        Md5,
        Sha1,
        Sha256,
        Sha384,
        Sha512
    };

    size_t HashLength(HashAlgorithm algorithm);

    // thin wrapper over the windows bcrypt hash api so we're not juggling raw handles everywhere
    class Hasher
    {
    public:
        explicit Hasher(HashAlgorithm algorithm);
        ~Hasher();

        Hasher(const Hasher&) = delete;
        Hasher& operator=(const Hasher&) = delete;

        void Update(const void* data, size_t size);
        void Update(const Bytes& data);
        Bytes Finish();

    private:
        void* handle = nullptr;
        size_t length = 0;
    };

    Bytes Hash(HashAlgorithm algorithm, const Bytes& data);

    // one AES key, does exactly one 16 byte block at a time.
    // all the real modes (CFB, OCB, key wrap) get built on top of this in OpenPgp.cpp
    class Aes
    {
    public:
        explicit Aes(const Bytes& key);
        ~Aes();

        Aes(const Aes&) = delete;
        Aes& operator=(const Aes&) = delete;

        void Encrypt(const uint8_t* input, uint8_t* output) const;
        void Decrypt(const uint8_t* input, uint8_t* output) const;

    private:
        void* handle = nullptr;
    };

    Bytes RandomBytes(size_t size);

    Bytes RsaEncrypt(const Bytes& modulus, const Bytes& exponent, const Bytes& message);
    Bytes RsaDecrypt(const Bytes& modulus, const Bytes& exponent, const Bytes& prime1, const Bytes& prime2, const Bytes& ciphertext);

    struct RsaKeyPair
    {
        Bytes n;
        Bytes e;
        Bytes d;
        Bytes p;
        Bytes q;
        Bytes u;

        RsaKeyPair() = default;
        RsaKeyPair(RsaKeyPair&&) = default;
        RsaKeyPair& operator=(RsaKeyPair&&) = default;
        RsaKeyPair(const RsaKeyPair&) = delete;
        RsaKeyPair& operator=(const RsaKeyPair&) = delete;
        ~RsaKeyPair();
    };

    // makes a fresh RSA key in the shape openpgp wants: p < q and u = p^-1 mod q
    RsaKeyPair RsaGenerate(unsigned bits);
    // PKCS#1 v1.5 signature over a sha256 digest, what our self-signatures use
    Bytes RsaSignSha256(const RsaKeyPair& key, const Bytes& digest);

    // zero stuff out before it gets freed so keys don't just hang around in ram
    void WipeMemory(void* data, size_t size);
    void Wipe(Bytes& data);
    void Wipe(std::string& data);
}
