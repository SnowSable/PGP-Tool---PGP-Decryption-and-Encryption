#include "Primitives.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>

namespace Pgp
{
    namespace
    {
        // opening a bcrypt provider is kinda slow so each one gets opened once and kept for the whole run
        class Provider
        {
        public:
            Provider(LPCWSTR algorithm, ULONG flags, LPCWSTR chainingMode = nullptr)
            {
                if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&handle, algorithm, nullptr, flags)))
                {
                    handle = nullptr;
                    return;
                }
                if (chainingMode)
                {
                    ULONG size = static_cast<ULONG>((wcslen(chainingMode) + 1) * sizeof(wchar_t));
                    if (!BCRYPT_SUCCESS(BCryptSetProperty(handle, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chainingMode)), size, 0)))
                    {
                        BCryptCloseAlgorithmProvider(handle, 0);
                        handle = nullptr;
                    }
                }
            }

            Provider(const Provider&) = delete;
            Provider& operator=(const Provider&) = delete;

            ~Provider()
            {
                if (handle)
                    BCryptCloseAlgorithmProvider(handle, 0);
            }

            BCRYPT_ALG_HANDLE Get() const
            {
                if (!handle)
                    throw Error("A required Windows cryptography provider is unavailable");
                return handle;
            }

        private:
            BCRYPT_ALG_HANDLE handle = nullptr;
        };

        BCRYPT_ALG_HANDLE HashProvider(HashAlgorithm algorithm)
        {
            static Provider md5(BCRYPT_MD5_ALGORITHM, 0);
            static Provider sha1(BCRYPT_SHA1_ALGORITHM, 0);
            static Provider sha256(BCRYPT_SHA256_ALGORITHM, 0);
            static Provider sha384(BCRYPT_SHA384_ALGORITHM, 0);
            static Provider sha512(BCRYPT_SHA512_ALGORITHM, 0);

            switch (algorithm)
            {
            case HashAlgorithm::Md5: return md5.Get();
            case HashAlgorithm::Sha1: return sha1.Get();
            case HashAlgorithm::Sha256: return sha256.Get();
            case HashAlgorithm::Sha384: return sha384.Get();
            case HashAlgorithm::Sha512: return sha512.Get();
            }
            throw Error("Unsupported hash algorithm");
        }

        // ECB on purpose, we only want the raw block cipher here. the actual modes are done by hand
        BCRYPT_ALG_HANDLE AesProvider()
        {
            static Provider aes(BCRYPT_AES_ALGORITHM, 0, BCRYPT_CHAIN_MODE_ECB);
            return aes.Get();
        }

        BCRYPT_ALG_HANDLE RsaProvider()
        {
            static Provider rsa(BCRYPT_RSA_ALGORITHM, 0);
            return rsa.Get();
        }

        // MPIs and bcrypt both hate leading zero bytes so chop them off first
        Bytes StripLeadingZeros(const Bytes& value)
        {
            auto first = std::find_if(value.begin(), value.end(), [](uint8_t b) { return b != 0; });
            return Bytes(first, value.end());
        }

        ULONG BitLength(const Bytes& value)
        {
            if (value.empty())
                return 0;
            ULONG bits = static_cast<ULONG>(value.size() - 1) * 8;
            for (uint8_t top = value[0]; top; top >>= 1)
                ++bits;
            return bits;
        }

        class KeyHandle
        {
        public:
            ~KeyHandle()
            {
                if (handle)
                    BCryptDestroyKey(handle);
            }

            BCRYPT_KEY_HANDLE handle = nullptr;
        };
    }

    size_t HashLength(HashAlgorithm algorithm)
    {
        switch (algorithm)
        {
        case HashAlgorithm::Md5: return 16;
        case HashAlgorithm::Sha1: return 20;
        case HashAlgorithm::Sha256: return 32;
        case HashAlgorithm::Sha384: return 48;
        case HashAlgorithm::Sha512: return 64;
        }
        return 0;
    }

    Hasher::Hasher(HashAlgorithm algorithm) : length(HashLength(algorithm))
    {
        BCRYPT_HASH_HANDLE created = nullptr;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(HashProvider(algorithm), &created, nullptr, 0, nullptr, 0, 0)))
            throw Error("Unable to create hash");
        handle = created;
    }

    Hasher::~Hasher()
    {
        if (handle)
            BCryptDestroyHash(static_cast<BCRYPT_HASH_HANDLE>(handle));
    }

    void Hasher::Update(const void* data, size_t size)
    {
        auto bytes = static_cast<const uint8_t*>(data);
        while (size > 0)
        {
            ULONG chunk = static_cast<ULONG>(std::min<size_t>(size, 0x40000000));
            if (!BCRYPT_SUCCESS(BCryptHashData(static_cast<BCRYPT_HASH_HANDLE>(handle), const_cast<PUCHAR>(bytes), chunk, 0)))
                throw Error("Unable to hash data");
            bytes += chunk;
            size -= chunk;
        }
    }

    void Hasher::Update(const Bytes& data)
    {
        Update(data.data(), data.size());
    }

    Bytes Hasher::Finish()
    {
        Bytes digest(length);
        if (!BCRYPT_SUCCESS(BCryptFinishHash(static_cast<BCRYPT_HASH_HANDLE>(handle), digest.data(), static_cast<ULONG>(digest.size()), 0)))
            throw Error("Unable to finish hash");
        return digest;
    }

    Bytes Hash(HashAlgorithm algorithm, const Bytes& data)
    {
        Hasher hasher(algorithm);
        hasher.Update(data);
        return hasher.Finish();
    }

    Aes::Aes(const Bytes& key)
    {
        if (key.size() != 16 && key.size() != 24 && key.size() != 32)
            throw Error("Invalid AES key length");
        BCRYPT_KEY_HANDLE created = nullptr;
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(AesProvider(), &created, nullptr, 0, const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
            throw Error("Unable to create AES key");
        handle = created;
    }

    Aes::~Aes()
    {
        if (handle)
            BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(handle));
    }

    void Aes::Encrypt(const uint8_t* input, uint8_t* output) const
    {
        uint8_t in[16];
        uint8_t out[16];
        std::memcpy(in, input, 16);
        ULONG written = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(static_cast<BCRYPT_KEY_HANDLE>(handle), in, 16, nullptr, nullptr, 0, out, 16, &written, 0)) || written != 16)
            throw Error("AES encryption failed");
        std::memcpy(output, out, 16);
    }

    void Aes::Decrypt(const uint8_t* input, uint8_t* output) const
    {
        uint8_t in[16];
        uint8_t out[16];
        std::memcpy(in, input, 16);
        ULONG written = 0;
        if (!BCRYPT_SUCCESS(BCryptDecrypt(static_cast<BCRYPT_KEY_HANDLE>(handle), in, 16, nullptr, nullptr, 0, out, 16, &written, 0)) || written != 16)
            throw Error("AES decryption failed");
        std::memcpy(output, out, 16);
    }

    Bytes RandomBytes(size_t size)
    {
        Bytes result(size);
        if (size && !BCRYPT_SUCCESS(BCryptGenRandom(nullptr, result.data(), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            throw Error("Unable to generate random data");
        return result;
    }

    // yeah basically this loads the recipient's n and e into windows and lets it do PKCS#1 v1.5 padding + encrypt.
    // gets called from BuildSessionKeyPacket, line 1123 in OpenPgp.cpp
    Bytes RsaEncrypt(const Bytes& modulus, const Bytes& exponent, const Bytes& message)
    {
        Bytes n = StripLeadingZeros(modulus);
        Bytes e = StripLeadingZeros(exponent);
        if (n.empty() || e.empty())
            throw Error("Invalid RSA public key");

        Bytes blob(sizeof(BCRYPT_RSAKEY_BLOB) + e.size() + n.size());
        auto header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
        header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header->BitLength = BitLength(n);
        header->cbPublicExp = static_cast<ULONG>(e.size());
        header->cbModulus = static_cast<ULONG>(n.size());
        header->cbPrime1 = 0;
        header->cbPrime2 = 0;
        std::memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB), e.data(), e.size());
        std::memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB) + e.size(), n.data(), n.size());

        KeyHandle key;
        if (!BCRYPT_SUCCESS(BCryptImportKeyPair(RsaProvider(), nullptr, BCRYPT_RSAPUBLIC_BLOB, &key.handle, blob.data(), static_cast<ULONG>(blob.size()), 0)))
            throw Error("The recipient RSA key could not be loaded");

        Bytes output(n.size());
        ULONG written = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(key.handle, const_cast<PUCHAR>(message.data()), static_cast<ULONG>(message.size()), nullptr, nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &written, BCRYPT_PAD_PKCS1)))
            throw Error("RSA encryption failed");
        output.resize(written);
        return output;
    }

    // same deal backwards. windows only needs e, n, p and q and works the rest out itself,
    // which is why d just gets thrown away in Unlock (OpenPgp.cpp line 1174)
    namespace
    {
        void ImportRsaPrivate(const Bytes& modulus, const Bytes& exponent, const Bytes& prime1, const Bytes& prime2, KeyHandle& key)
        {
            Bytes n = StripLeadingZeros(modulus);
            Bytes e = StripLeadingZeros(exponent);
            Bytes p = StripLeadingZeros(prime1);
            Bytes q = StripLeadingZeros(prime2);
            if (n.empty() || e.empty() || p.empty() || q.empty())
                throw Error("Invalid RSA private key");

            Bytes blob(sizeof(BCRYPT_RSAKEY_BLOB) + e.size() + n.size() + p.size() + q.size());
            auto header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(blob.data());
            header->Magic = BCRYPT_RSAPRIVATE_MAGIC;
            header->BitLength = BitLength(n);
            header->cbPublicExp = static_cast<ULONG>(e.size());
            header->cbModulus = static_cast<ULONG>(n.size());
            header->cbPrime1 = static_cast<ULONG>(p.size());
            header->cbPrime2 = static_cast<ULONG>(q.size());
            uint8_t* cursor = blob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
            for (const Bytes* part : { &e, &n, &p, &q })
            {
                std::memcpy(cursor, part->data(), part->size());
                cursor += part->size();
            }

            NTSTATUS status = BCryptImportKeyPair(RsaProvider(), nullptr, BCRYPT_RSAPRIVATE_BLOB, &key.handle, blob.data(), static_cast<ULONG>(blob.size()), 0);
            Wipe(blob);
            Wipe(p);
            Wipe(q);
            if (!BCRYPT_SUCCESS(status))
                throw Error("The RSA private key could not be loaded");
        }

        bool LessThan(const Bytes& a, const Bytes& b)
        {
            if (a.size() != b.size())
                return a.size() < b.size();
            return std::memcmp(a.data(), b.data(), a.size()) < 0;
        }
    }

    Bytes RsaDecrypt(const Bytes& modulus, const Bytes& exponent, const Bytes& prime1, const Bytes& prime2, const Bytes& ciphertext)
    {
        Bytes n = StripLeadingZeros(modulus);
        Bytes c = StripLeadingZeros(ciphertext);
        if (c.size() > n.size())
            throw Error("Invalid RSA ciphertext");

        KeyHandle key;
        ImportRsaPrivate(modulus, exponent, prime1, prime2, key);

        // bcrypt wants the ciphertext exactly modulus sized, so pad the front with zeros
        Bytes input(n.size() - c.size(), 0);
        input.insert(input.end(), c.begin(), c.end());
        Bytes output(n.size());
        ULONG written = 0;
        if (!BCRYPT_SUCCESS(BCryptDecrypt(key.handle, input.data(), static_cast<ULONG>(input.size()), nullptr, nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &written, BCRYPT_PAD_PKCS1)))
            throw Error("RSA decryption failed");
        output.resize(written);
        return output;
    }

    RsaKeyPair::~RsaKeyPair()
    {
        Wipe(d);
        Wipe(p);
        Wipe(q);
        Wipe(u);
    }

    // yeah basically windows makes the key, we export the whole private blob and rearrange it for openpgp.
    // bcrypt's coefficient is prime2^-1 mod prime1, openpgp wants u = p^-1 mod q with p < q,
    // so we call prime2 "p" and prime1 "q". only works when prime2 < prime1, so we just reroll until it is
    // (coin flip, usually 1 or 2 goes) instead of writing big number maths to recompute u
    RsaKeyPair RsaGenerate(unsigned bits)
    {
        for (;;)
        {
            KeyHandle key;
            if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(RsaProvider(), &key.handle, bits, 0)) || !BCRYPT_SUCCESS(BCryptFinalizeKeyPair(key.handle, 0)))
                throw Error("RSA key generation failed");

            ULONG size = 0;
            if (!BCRYPT_SUCCESS(BCryptExportKey(key.handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &size, 0)))
                throw Error("RSA key export failed");
            Bytes blob(size);
            if (!BCRYPT_SUCCESS(BCryptExportKey(key.handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, blob.data(), size, &size, 0)))
                throw Error("RSA key export failed");

            BCRYPT_RSAKEY_BLOB header;
            std::memcpy(&header, blob.data(), sizeof(header));
            const uint8_t* cursor = blob.data() + sizeof(header);
            auto take = [&cursor](ULONG count)
            {
                Bytes part(cursor, cursor + count);
                cursor += count;
                return part;
            };

            RsaKeyPair pair;
            pair.e = StripLeadingZeros(take(header.cbPublicExp));
            pair.n = StripLeadingZeros(take(header.cbModulus));
            Bytes prime1 = take(header.cbPrime1);
            Bytes prime2 = take(header.cbPrime2);
            Bytes exponent1 = take(header.cbPrime1);
            Bytes exponent2 = take(header.cbPrime2);
            Bytes coefficient = take(header.cbPrime1);
            Bytes privateExponent = take(header.cbModulus);
            Wipe(blob);
            Wipe(exponent1);
            Wipe(exponent2);

            pair.p = StripLeadingZeros(prime2);
            pair.q = StripLeadingZeros(prime1);
            pair.u = StripLeadingZeros(coefficient);
            pair.d = StripLeadingZeros(privateExponent);
            Wipe(prime1);
            Wipe(prime2);
            Wipe(coefficient);
            Wipe(privateExponent);

            if (LessThan(pair.p, pair.q))
                return pair;
        }
    }

    Bytes RsaSignSha256(const RsaKeyPair& pair, const Bytes& digest)
    {
        if (digest.size() != 32)
            throw Error("Invalid SHA-256 digest");

        KeyHandle key;
        ImportRsaPrivate(pair.n, pair.e, pair.p, pair.q, key);

        BCRYPT_PKCS1_PADDING_INFO padding = { BCRYPT_SHA256_ALGORITHM };
        Bytes signature(StripLeadingZeros(pair.n).size());
        ULONG written = 0;
        if (!BCRYPT_SUCCESS(BCryptSignHash(key.handle, &padding, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), signature.data(), static_cast<ULONG>(signature.size()), &written, BCRYPT_PAD_PKCS1)))
            throw Error("RSA signing failed");
        signature.resize(written);
        return signature;
    }

    void WipeMemory(void* data, size_t size)
    {
        if (data && size)
            SecureZeroMemory(data, size);
    }

    void Wipe(Bytes& data)
    {
        if (!data.empty())
            SecureZeroMemory(data.data(), data.size());
        data.clear();
    }

    void Wipe(std::string& data)
    {
        if (!data.empty())
            SecureZeroMemory(data.data(), data.size());
        data.clear();
    }
}
