#include "OpenPgp.h"

#include "Armor.h"
#include "Curve25519.h"
#include "Inflate.h"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace Pgp
{
    namespace
    {
        // packet type numbers from rfc 9580 section 5, only the ones we actually touch
        enum Tag
        {
            TagSessionKey = 1,
            TagSignature = 2,
            TagSecretKey = 5,
            TagPublicKey = 6,
            TagSecretSubkey = 7,
            TagCompressed = 8,
            TagSymmetricEncrypted = 9,
            TagLiteral = 11,
            TagUserId = 13,
            TagPublicSubkey = 14,
            TagIntegrityProtected = 18,
            TagOcbEncrypted = 20
        };

        enum Algorithm
        {
            AlgorithmRsa = 1,
            AlgorithmRsaEncrypt = 2,
            AlgorithmRsaSign = 3,
            AlgorithmElgamal = 16,
            AlgorithmDsa = 17,
            AlgorithmEcdh = 18,
            AlgorithmEcdsa = 19,
            AlgorithmEdDsaLegacy = 22,
            AlgorithmX25519 = 25,
            AlgorithmX448 = 26,
            AlgorithmEd25519 = 27,
            AlgorithmEd448 = 28
        };

        constexpr int CipherAes256 = 9;
        constexpr size_t BlockSize = 16;

        // 1.3.6.1.4.1.3029.1.5.1, the oid gpg uses for cv25519 encryption subkeys
        const Bytes Curve25519Oid = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 };
        // yes this string is literally in the spec, 20 bytes including the trailing spaces. goes into the ECDH KDF
        const char AnonymousSender[] = "Anonymous Sender    ";

        // bounds checked reader over a byte buffer, throws instead of reading off the end
        class Reader
        {
        public:
            Reader(const uint8_t* data, size_t size) : data(data), size(size) {}
            explicit Reader(const Bytes& bytes) : Reader(bytes.data(), bytes.size()) {}

            uint8_t Byte()
            {
                Need(1);
                return data[position++];
            }

            uint32_t U16()
            {
                Need(2);
                uint32_t value = (uint32_t(data[position]) << 8) | data[position + 1];
                position += 2;
                return value;
            }

            uint32_t U32()
            {
                Need(4);
                uint32_t value = (uint32_t(data[position]) << 24) | (uint32_t(data[position + 1]) << 16) | (uint32_t(data[position + 2]) << 8) | data[position + 3];
                position += 4;
                return value;
            }

            Bytes Take(size_t count)
            {
                Need(count);
                Bytes result(data + position, data + position + count);
                position += count;
                return result;
            }

            Bytes Mpi()
            {
                uint32_t bits = U16();
                return Take((bits + 7) / 8);
            }

            Bytes Rest()
            {
                return Take(Remaining());
            }

            void Skip(size_t count)
            {
                Need(count);
                position += count;
            }

            size_t Remaining() const { return size - position; }
            size_t Position() const { return position; }

        private:
            void Need(size_t count) const
            {
                if (count > size - position)
                    throw Error("The PGP data is malformed or incomplete");
            }

            const uint8_t* data;
            size_t size;
            size_t position = 0;
        };

        struct Packet
        {
            int tag = 0;
            Bytes body;
        };

        struct S2K
        {
            int type = -1;
            int hash = 0;
            Bytes salt;
            size_t count = 0;
            bool dummy = false;
        };

        // one primary key or subkey out of a key block. always has the public bits,
        // only has the secret bits after Unlock (line 1149) has run
        struct Key
        {
            int version = 0;
            uint32_t created = 0;
            int algorithm = 0;
            bool subkey = false;
            bool secret = false;
            bool supported = false;
            std::string problem;

            Bytes fingerprint;
            Bytes keyId;
            Bytes rsaN;
            Bytes rsaE;
            Bytes curveOid;
            Bytes ecPoint;
            Bytes kdfParams;
            int kdfHash = 0;
            int kdfCipher = 0;

            int flags = -1;
            uint32_t flagsTime = 0;
            uint32_t expiresAfter = 0;
            uint32_t expiryTime = 0;
            bool revoked = false;

            int protection = 0;
            int protectionCipher = 0;
            S2K s2k;
            Bytes iv;
            Bytes secretData;
            bool unlocked = false;
            Bytes rsaP;
            Bytes rsaQ;
            Bytes ecSecret;

            Key() = default;
            Key(Key&&) = default;
            Key& operator=(Key&&) = default;
            // no copies, otherwise secret material ends up scattered all over the heap
            Key(const Key&) = delete;
            Key& operator=(const Key&) = delete;

            ~Key()
            {
                Wipe(secretData);
                Wipe(rsaP);
                Wipe(rsaQ);
                Wipe(ecSecret);
            }
        };

        struct Keyring
        {
            std::vector<Key> keys;
            std::string userId;
            std::string type;
        };

        struct SessionKey
        {
            int cipher = 0;
            Bytes key;

            ~SessionKey()
            {
                Wipe(key);
            }
        };

        bool IsBlank(std::string_view text)
        {
            return text.find_first_not_of(" \t\r\n") == std::string_view::npos;
        }

        std::string Hex(const Bytes& data)
        {
            static const char digits[] = "0123456789ABCDEF";
            std::string out;
            for (uint8_t byte : data)
            {
                out += digits[byte >> 4];
                out += digits[byte & 15];
            }
            return out;
        }

        void Append(Bytes& out, const Bytes& data)
        {
            out.insert(out.end(), data.begin(), data.end());
        }

        void AppendU32(Bytes& out, uint32_t value)
        {
            out.push_back(static_cast<uint8_t>(value >> 24));
            out.push_back(static_cast<uint8_t>(value >> 16));
            out.push_back(static_cast<uint8_t>(value >> 8));
            out.push_back(static_cast<uint8_t>(value));
        }

        void AppendU64(Bytes& out, uint64_t value)
        {
            for (int shift = 56; shift >= 0; shift -= 8)
                out.push_back(static_cast<uint8_t>(value >> shift));
        }

        uint32_t ReadU32(const uint8_t* data)
        {
            return (uint32_t(data[0]) << 24) | (uint32_t(data[1]) << 16) | (uint32_t(data[2]) << 8) | data[3];
        }

        bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t size)
        {
            uint8_t difference = 0;
            for (size_t i = 0; i < size; ++i)
                difference |= a[i] ^ b[i];
            return difference == 0;
        }

        // the dumb 16 bit sum openpgp uses as a checksum for session keys and old style secret keys
        uint16_t Checksum(const uint8_t* data, size_t size)
        {
            uint32_t sum = 0;
            for (size_t i = 0; i < size; ++i)
                sum += data[i];
            return static_cast<uint16_t>(sum & 0xFFFF);
        }

        HashAlgorithm HashFromId(int id)
        {
            switch (id)
            {
            case 1: return HashAlgorithm::Md5;
            case 2: return HashAlgorithm::Sha1;
            case 8: return HashAlgorithm::Sha256;
            case 9: return HashAlgorithm::Sha384;
            case 10: return HashAlgorithm::Sha512;
            }
            throw Error("The key uses an unsupported hash algorithm (" + std::to_string(id) + ")");
        }

        std::string CipherName(int id)
        {
            switch (id)
            {
            case 1: return "IDEA";
            case 2: return "TripleDES";
            case 3: return "CAST5";
            case 4: return "Blowfish";
            case 10: return "Twofish";
            case 11:
            case 12:
            case 13: return "Camellia";
            }
            return "algorithm " + std::to_string(id);
        }

        size_t CipherKeyLength(int id)
        {
            switch (id)
            {
            case 7: return 16;
            case 8: return 24;
            case 9: return 32;
            }
            throw Error("Unsupported cipher " + CipherName(id) + ", only AES is supported");
        }

        // splits a binary blob into packets. handles old and new style headers plus the
        // partial body length thing gpg does when it streams bigger messages
        std::vector<Packet> ReadPackets(const uint8_t* data, size_t size)
        {
            std::vector<Packet> packets;
            Reader reader(data, size);
            while (reader.Remaining() > 0)
            {
                uint8_t header = reader.Byte();
                if (!(header & 0x80))
                    throw Error("The PGP data is malformed or incomplete");

                Packet packet;
                if (header & 0x40)
                {
                    packet.tag = header & 0x3F;
                    for (;;)
                    {
                        uint8_t first = reader.Byte();
                        size_t length = 0;
                        bool partial = false;
                        if (first < 192)
                        {
                            length = first;
                        }
                        else if (first < 224)
                        {
                            length = ((size_t(first) - 192) << 8) + reader.Byte() + 192;
                        }
                        else if (first == 255)
                        {
                            length = reader.U32();
                        }
                        else
                        {
                            // partial length, more chunks follow so keep looping and glue them together
                            length = size_t(1) << (first & 0x1F);
                            partial = true;
                        }
                        Append(packet.body, reader.Take(length));
                        if (!partial)
                            break;
                    }
                }
                else
                {
                    packet.tag = (header >> 2) & 0x0F;
                    switch (header & 3)
                    {
                    case 0: packet.body = reader.Take(reader.Byte()); break;
                    case 1: packet.body = reader.Take(reader.U16()); break;
                    case 2: packet.body = reader.Take(reader.U32()); break;
                    default: packet.body = reader.Rest(); break;
                    }
                }
                packets.push_back(std::move(packet));
            }
            return packets;
        }

        void WritePacket(Bytes& out, int tag, const Bytes& body)
        {
            out.push_back(static_cast<uint8_t>(0xC0 | tag));
            size_t length = body.size();
            if (length < 192)
            {
                out.push_back(static_cast<uint8_t>(length));
            }
            else if (length < 8384)
            {
                length -= 192;
                out.push_back(static_cast<uint8_t>((length >> 8) + 192));
                out.push_back(static_cast<uint8_t>(length & 0xFF));
            }
            else
            {
                out.push_back(0xFF);
                AppendU32(out, static_cast<uint32_t>(length));
            }
            Append(out, body);
        }

        void WriteMpi(Bytes& out, const Bytes& value)
        {
            size_t start = 0;
            while (start < value.size() && value[start] == 0)
                ++start;
            uint32_t bits = 0;
            if (start < value.size())
            {
                bits = static_cast<uint32_t>(value.size() - start - 1) * 8;
                for (uint8_t top = value[start]; top; top >>= 1)
                    ++bits;
            }
            out.push_back(static_cast<uint8_t>(bits >> 8));
            out.push_back(static_cast<uint8_t>(bits));
            out.insert(out.end(), value.begin() + start, value.end());
        }

        Bytes PadLeft(const Bytes& value, size_t size)
        {
            if (value.size() >= size)
                return Bytes(value.end() - size, value.end());
            Bytes out(size - value.size(), 0);
            Append(out, value);
            return out;
        }

        // plain CFB with full 16 byte feedback, which is what SEIPD v1 uses. none of the old openpgp resync weirdness
        Bytes CfbEncrypt(const Aes& aes, const uint8_t* iv, const Bytes& data)
        {
            Bytes out(data.size());
            uint8_t feedback[BlockSize];
            uint8_t stream[BlockSize];
            std::memcpy(feedback, iv, BlockSize);
            for (size_t i = 0; i < data.size(); i += BlockSize)
            {
                aes.Encrypt(feedback, stream);
                size_t count = std::min(BlockSize, data.size() - i);
                for (size_t j = 0; j < count; ++j)
                {
                    out[i + j] = data[i + j] ^ stream[j];
                    feedback[j] = out[i + j];
                }
            }
            return out;
        }

        Bytes CfbDecrypt(const Aes& aes, const uint8_t* iv, const uint8_t* data, size_t size)
        {
            Bytes out(size);
            uint8_t feedback[BlockSize];
            uint8_t stream[BlockSize];
            std::memcpy(feedback, iv, BlockSize);
            for (size_t i = 0; i < size; i += BlockSize)
            {
                aes.Encrypt(feedback, stream);
                size_t count = std::min(BlockSize, size - i);
                for (size_t j = 0; j < count; ++j)
                {
                    feedback[j] = data[i + j];
                    out[i + j] = data[i + j] ^ stream[j];
                }
            }
            return out;
        }

        // rfc 3394 key wrap, ECDH uses it to wrap the session key. 6 rounds over 8 byte chunks
        Bytes AesKeyWrap(const Bytes& kek, const Bytes& plain)
        {
            if (plain.size() % 8 != 0 || plain.size() < 16)
                throw Error("Invalid key wrap input");
            Aes aes(kek);
            size_t n = plain.size() / 8;
            uint8_t a[8];
            std::memset(a, 0xA6, 8);
            Bytes r = plain;
            uint8_t block[16];
            for (size_t j = 0; j < 6; ++j)
            {
                for (size_t i = 0; i < n; ++i)
                {
                    std::memcpy(block, a, 8);
                    std::memcpy(block + 8, r.data() + i * 8, 8);
                    aes.Encrypt(block, block);
                    uint64_t t = n * j + i + 1;
                    for (int k = 0; k < 8; ++k)
                        a[k] = block[k] ^ static_cast<uint8_t>(t >> (56 - 8 * k));
                    std::memcpy(r.data() + i * 8, block + 8, 8);
                }
            }
            Bytes out(a, a + 8);
            Append(out, r);
            return out;
        }

        Bytes AesKeyUnwrap(const Bytes& kek, const Bytes& wrapped)
        {
            if (wrapped.size() % 8 != 0 || wrapped.size() < 24)
                throw Error("The session key could not be unwrapped");
            Aes aes(kek);
            size_t n = wrapped.size() / 8 - 1;
            uint8_t a[8];
            std::memcpy(a, wrapped.data(), 8);
            Bytes r(wrapped.begin() + 8, wrapped.end());
            uint8_t block[16];
            for (size_t j = 6; j-- > 0;)
            {
                for (size_t i = n; i-- > 0;)
                {
                    uint64_t t = n * j + i + 1;
                    for (int k = 0; k < 8; ++k)
                        block[k] = a[k] ^ static_cast<uint8_t>(t >> (56 - 8 * k));
                    std::memcpy(block + 8, r.data() + i * 8, 8);
                    aes.Decrypt(block, block);
                    std::memcpy(a, block, 8);
                    std::memcpy(r.data() + i * 8, block + 8, 8);
                }
            }
            uint8_t expected[8];
            std::memset(expected, 0xA6, 8);
            if (!ConstantTimeEqual(a, expected, 8))
            {
                Wipe(r);
                throw Error("The session key could not be unwrapped, the private key does not match this message");
            }
            return r;
        }

        // AES-OCB from rfc 7253, decrypt only. gpg 2.3+ uses it for its AEAD packets (tag 20).
        // DecryptOcb on line 1320 drives it chunk by chunk
        class Ocb
        {
        public:
            explicit Ocb(const Aes& aes) : aes(aes)
            {
                uint8_t zero[BlockSize] = {};
                aes.Encrypt(zero, lStar);
                Double(lStar, lDollar);
                Double(lDollar, l[0]);
                for (int i = 1; i < 64; ++i)
                    Double(l[i - 1], l[i]);
            }

            Bytes Decrypt(const Bytes& nonce, const Bytes& associated, const uint8_t* ciphertext, size_t size, const uint8_t* tag) const
            {
                uint8_t offset[BlockSize];
                InitialOffset(nonce, offset);
                uint8_t checksum[BlockSize] = {};
                Bytes out(size);
                uint8_t block[BlockSize];

                size_t blocks = size / BlockSize;
                for (size_t i = 1; i <= blocks; ++i)
                {
                    Xor(offset, l[Ntz(i)]);
                    const uint8_t* source = ciphertext + (i - 1) * BlockSize;
                    for (size_t j = 0; j < BlockSize; ++j)
                        block[j] = source[j] ^ offset[j];
                    aes.Decrypt(block, block);
                    for (size_t j = 0; j < BlockSize; ++j)
                    {
                        block[j] ^= offset[j];
                        out[(i - 1) * BlockSize + j] = block[j];
                        checksum[j] ^= block[j];
                    }
                }

                size_t remaining = size % BlockSize;
                if (remaining)
                {
                    Xor(offset, lStar);
                    uint8_t pad[BlockSize];
                    aes.Encrypt(offset, pad);
                    size_t base = blocks * BlockSize;
                    for (size_t j = 0; j < remaining; ++j)
                    {
                        out[base + j] = ciphertext[base + j] ^ pad[j];
                        checksum[j] ^= out[base + j];
                    }
                    checksum[remaining] ^= 0x80;
                }

                uint8_t expected[BlockSize];
                for (size_t j = 0; j < BlockSize; ++j)
                    expected[j] = checksum[j] ^ offset[j] ^ lDollar[j];
                aes.Encrypt(expected, expected);
                uint8_t hash[BlockSize];
                Hash(associated, hash);
                Xor(expected, hash);

                if (!ConstantTimeEqual(expected, tag, BlockSize))
                {
                    Wipe(out);
                    throw Error("The message failed its integrity check, it is corrupt or the key is wrong");
                }
                return out;
            }

        private:
            static void Double(const uint8_t* in, uint8_t* out)
            {
                uint8_t carry = in[0] >> 7;
                for (size_t i = 0; i < BlockSize - 1; ++i)
                    out[i] = static_cast<uint8_t>((in[i] << 1) | (in[i + 1] >> 7));
                out[BlockSize - 1] = static_cast<uint8_t>((in[BlockSize - 1] << 1) ^ (carry ? 0x87 : 0));
            }

            static void Xor(uint8_t* target, const uint8_t* source)
            {
                for (size_t i = 0; i < BlockSize; ++i)
                    target[i] ^= source[i];
            }

            static int Ntz(size_t value)
            {
                int count = 0;
                while (!(value & 1))
                {
                    value >>= 1;
                    ++count;
                }
                return count;
            }

            void InitialOffset(const Bytes& nonce, uint8_t* offset) const
            {
                if (nonce.empty() || nonce.size() > 15)
                    throw Error("Invalid OCB nonce");
                uint8_t n[BlockSize] = {};
                // nonce gets padded to 16 bytes with a single 1 bit right in front of it.
                // the top 7 bits are the tag length mod 128, which is 0 for our 128 bit tags
                n[15 - nonce.size()] = 0x01;
                std::memcpy(n + BlockSize - nonce.size(), nonce.data(), nonce.size());
                int bottom = n[15] & 0x3F;
                n[15] &= 0xC0;
                uint8_t top[BlockSize];
                aes.Encrypt(n, top);
                uint8_t stretch[24];
                std::memcpy(stretch, top, BlockSize);
                for (int i = 0; i < 8; ++i)
                    // the 'stretch' step from the rfc, then we grab 128 bits starting at bit 'bottom'
                    stretch[16 + i] = top[i] ^ top[i + 1];
                int byteShift = bottom / 8;
                int bitShift = bottom % 8;
                for (int i = 0; i < 16; ++i)
                {
                    int value = stretch[i + byteShift] << bitShift;
                    if (bitShift)
                        value |= stretch[i + byteShift + 1] >> (8 - bitShift);
                    offset[i] = static_cast<uint8_t>(value);
                }
            }

            void Hash(const Bytes& associated, uint8_t* sum) const
            {
                uint8_t offset[BlockSize] = {};
                uint8_t block[BlockSize];
                std::memset(sum, 0, BlockSize);
                size_t blocks = associated.size() / BlockSize;
                for (size_t i = 1; i <= blocks; ++i)
                {
                    Xor(offset, l[Ntz(i)]);
                    for (size_t j = 0; j < BlockSize; ++j)
                        block[j] = associated[(i - 1) * BlockSize + j] ^ offset[j];
                    aes.Encrypt(block, block);
                    Xor(sum, block);
                }
                size_t remaining = associated.size() % BlockSize;
                if (remaining)
                {
                    Xor(offset, lStar);
                    std::memset(block, 0, BlockSize);
                    std::memcpy(block, associated.data() + blocks * BlockSize, remaining);
                    block[remaining] = 0x80;
                    Xor(block, offset);
                    aes.Encrypt(block, block);
                    Xor(sum, block);
                }
            }

            const Aes& aes;
            uint8_t lStar[BlockSize];
            uint8_t lDollar[BlockSize];
            uint8_t l[64][BlockSize];
        };

        // reads how the passphrase gets turned into a key. type 3 (iterated + salted) is what gpg uses.
        // 101 is gpg's own 'no secret here, it's on a smartcard' marker
        S2K ReadS2K(Reader& reader)
        {
            S2K s2k;
            s2k.type = reader.Byte();
            switch (s2k.type)
            {
            case 0:
                s2k.hash = reader.Byte();
                break;
            case 1:
                s2k.hash = reader.Byte();
                s2k.salt = reader.Take(8);
                break;
            case 3:
            {
                s2k.hash = reader.Byte();
                s2k.salt = reader.Take(8);
                int c = reader.Byte();
                // the count is squashed into one byte, this is the official formula to unpack it
                s2k.count = size_t(16 + (c & 15)) << ((c >> 4) + 6);
                break;
            }
            case 101:
                s2k.hash = reader.Byte();
                reader.Skip(3);
                reader.Byte();
                s2k.dummy = true;
                break;
            default:
                throw Error("The private key uses an unsupported passphrase protection (S2K type " + std::to_string(s2k.type) + ")");
            }
            return s2k;
        }

        // hashes salt+passphrase over and over until 'count' bytes have gone through.
        // we fill a ~64k buffer with copies so bcrypt gets big chunks instead of millions of tiny calls
        Bytes DeriveKey(const S2K& s2k, std::string_view passphrase, size_t length)
        {
            HashAlgorithm hash = HashFromId(s2k.hash);
            Bytes result;
            for (size_t round = 0; result.size() < length; ++round)
            {
                Hasher hasher(hash);
                Bytes zeros(round, 0);
                hasher.Update(zeros);
                if (s2k.type == 0)
                {
                    hasher.Update(passphrase.data(), passphrase.size());
                }
                else if (s2k.type == 1)
                {
                    hasher.Update(s2k.salt);
                    hasher.Update(passphrase.data(), passphrase.size());
                }
                else
                {
                    Bytes unit = s2k.salt;
                    unit.insert(unit.end(), passphrase.begin(), passphrase.end());
                    size_t total = std::max(s2k.count, unit.size());
                    size_t repeats = std::max<size_t>(1, 65536 / unit.size());
                    Bytes buffer;
                    buffer.reserve(unit.size() * repeats);
                    for (size_t i = 0; i < repeats; ++i)
                        Append(buffer, unit);
                    while (total >= buffer.size())
                    {
                        hasher.Update(buffer);
                        total -= buffer.size();
                    }
                    hasher.Update(buffer.data(), total);
                    Wipe(buffer);
                    Wipe(unit);
                }
                Append(result, hasher.Finish());
            }
            result.resize(length);
            return result;
        }

        struct SignatureInfo
        {
            int type = 0;
            uint32_t created = 0;
            int flags = -1;
            bool hasExpiry = false;
            uint32_t expiresAfter = 0;
        };

        // we don't verify signatures, just read key flags, expiry and creation time out of the self sigs.
        // (if someone can edit your key block they can do way worse than this anyway)
        bool ParseSignature(const Bytes& body, SignatureInfo& info)
        {
            try
            {
                Reader reader(body);
                if (reader.Byte() != 4)
                    return false;
                info.type = reader.Byte();
                reader.Skip(2);
                Bytes hashed = reader.Take(reader.U16());
                Reader sub(hashed);
                while (sub.Remaining() > 0)
                {
                    uint8_t first = sub.Byte();
                    size_t length = 0;
                    if (first < 192)
                        length = first;
                    else if (first < 255)
                        length = ((size_t(first) - 192) << 8) + sub.Byte() + 192;
                    else
                        length = sub.U32();
                    if (length == 0)
                        return false;
                    Bytes data = sub.Take(length);
                    int type = data[0] & 0x7F;
                    if (type == 2 && data.size() >= 5)
                        info.created = ReadU32(data.data() + 1);
                    else if (type == 9 && data.size() >= 5)
                    {
                        info.hasExpiry = true;
                        info.expiresAfter = ReadU32(data.data() + 1);
                    }
                    else if (type == 27 && data.size() >= 2)
                        info.flags = data[1];
                }
                return true;
            }
            catch (const Error&)
            {
                return false;
            }
        }

        bool IsRsa(int algorithm)
        {
            return algorithm == AlgorithmRsa || algorithm == AlgorithmRsaEncrypt;
        }

        // parses one key packet. every algorithm gets read far enough to compute the fingerprint,
        // even ones we can't encrypt with, so key IDs always line up with what gpg shows
        Key ParseKeyPacket(const Packet& packet)
        {
            Key key;
            key.subkey = packet.tag == TagSecretSubkey || packet.tag == TagPublicSubkey;
            key.secret = packet.tag == TagSecretKey || packet.tag == TagSecretSubkey;

            Reader reader(packet.body);
            key.version = reader.Byte();
            if (key.version != 4)
            {
                key.problem = "Version " + std::to_string(key.version) + " keys are not supported, only version 4 keys are";
                return key;
            }
            key.created = reader.U32();
            key.algorithm = reader.Byte();

            switch (key.algorithm)
            {
            case AlgorithmRsa:
            case AlgorithmRsaEncrypt:
            case AlgorithmRsaSign:
                key.rsaN = reader.Mpi();
                key.rsaE = reader.Mpi();
                key.supported = key.algorithm != AlgorithmRsaSign;
                break;
            case AlgorithmElgamal:
                reader.Mpi();
                reader.Mpi();
                reader.Mpi();
                key.problem = "Elgamal encryption keys are not supported, the key needs an RSA or Curve25519 encryption subkey";
                break;
            case AlgorithmDsa:
                reader.Mpi();
                reader.Mpi();
                reader.Mpi();
                reader.Mpi();
                break;
            case AlgorithmEcdh:
            {
                key.curveOid = reader.Take(reader.Byte());
                key.ecPoint = reader.Mpi();
                uint8_t kdfLength = reader.Byte();
                Bytes kdf = reader.Take(kdfLength);
                key.kdfParams.push_back(kdfLength);
                Append(key.kdfParams, kdf);
                if (kdfLength == 3 && kdf[0] == 1)
                {
                    key.kdfHash = kdf[1];
                    key.kdfCipher = kdf[2];
                }
                if (key.curveOid != Curve25519Oid)
                    key.problem = "Only Curve25519 ECDH keys are supported, NIST and Brainpool curves are not";
                else if (key.ecPoint.size() != 33 || key.ecPoint[0] != 0x40 || kdfLength != 3)
                    key.problem = "The Curve25519 key is malformed";
                else
                    key.supported = true;
                break;
            }
            case AlgorithmEcdsa:
            case AlgorithmEdDsaLegacy:
                reader.Take(reader.Byte());
                reader.Mpi();
                break;
            case AlgorithmX25519:
            case AlgorithmX448:
                reader.Skip(key.algorithm == AlgorithmX25519 ? 32 : 56);
                key.problem = "X25519 and X448 keys in the RFC 9580 format are not supported";
                break;
            case AlgorithmEd25519:
                reader.Skip(32);
                break;
            case AlgorithmEd448:
                reader.Skip(57);
                break;
            default:
                key.problem = "The key uses an unknown public key algorithm (" + std::to_string(key.algorithm) + ")";
                return key;
            }

            size_t publicEnd = reader.Position();
            // v4 fingerprint = sha1 of 0x99, a 2 byte length, then the public part of the packet. key ID is the last 8 bytes
            Hasher fingerprint(HashAlgorithm::Sha1);
            uint8_t prefix[3] = { 0x99, static_cast<uint8_t>(publicEnd >> 8), static_cast<uint8_t>(publicEnd) };
            fingerprint.Update(prefix, 3);
            fingerprint.Update(packet.body.data(), publicEnd);
            key.fingerprint = fingerprint.Finish();
            key.keyId.assign(key.fingerprint.end() - 8, key.fingerprint.end());

            if (!key.secret || !key.supported)
                return key;

            // 0 = not encrypted, 254 = encrypted + sha1 check (gpg default), 255 = encrypted + weak 2 byte check,
            // anything else is ancient pgp 2 style where the byte itself is the cipher id
            key.protection = reader.Byte();
            if (key.protection == 0)
            {
                key.secretData = reader.Rest();
            }
            else if (key.protection == 254 || key.protection == 255)
            {
                key.protectionCipher = reader.Byte();
                try
                {
                    key.s2k = ReadS2K(reader);
                }
                catch (const Error& error)
                {
                    key.problem = error.what();
                    return key;
                }
                if (key.s2k.dummy)
                    return key;
                if (key.protectionCipher < 7 || key.protectionCipher > 9)
                {
                    key.problem = "The private key is protected with " + CipherName(key.protectionCipher) + ", only AES protected keys are supported";
                    return key;
                }
                key.iv = reader.Take(BlockSize);
                key.secretData = reader.Rest();
            }
            else if (key.protection == 253)
            {
                key.problem = "AEAD protected private keys are not supported";
            }
            else
            {
                key.protectionCipher = key.protection;
                key.s2k.type = 0;
                key.s2k.hash = 1;
                if (key.protectionCipher < 7 || key.protectionCipher > 9)
                {
                    key.problem = "The private key is protected with " + CipherName(key.protectionCipher) + ", only AES protected keys are supported";
                    return key;
                }
                key.iv = reader.Take(BlockSize);
                key.secretData = reader.Rest();
            }
            return key;
        }

        // turns pasted armored text into a list of keys + the first user id.
        // signatures get matched to whichever key came right before them
        Keyring ParseKeyring(std::string_view armored)
        {
            Keyring ring;
            Bytes data = Dearmor(armored, ring.type);
            if (ring.type.find("MESSAGE") != std::string::npos)
            {
                Wipe(data);
                throw Error("A PGP message was pasted where a key was expected");
            }

            std::vector<Packet> packets;
            try
            {
                packets = ReadPackets(data.data(), data.size());
            }
            catch (...)
            {
                Wipe(data);
                throw;
            }
            Wipe(data);
            ring.keys.reserve(packets.size());
            Key* current = nullptr;
            for (const Packet& packet : packets)
            {
                switch (packet.tag)
                {
                case TagSecretKey:
                case TagPublicKey:
                case TagSecretSubkey:
                case TagPublicSubkey:
                    ring.keys.push_back(ParseKeyPacket(packet));
                    current = &ring.keys.back();
                    break;
                case TagUserId:
                    if (ring.userId.empty())
                        ring.userId.assign(packet.body.begin(), packet.body.end());
                    break;
                case TagSignature:
                {
                    SignatureInfo info;
                    if (!current || !ParseSignature(packet.body, info))
                        break;
                    bool binding = current->subkey ? info.type == 0x18 : (info.type >= 0x10 && info.type <= 0x13) || info.type == 0x1F;
                    bool revocation = current->subkey ? info.type == 0x28 : info.type == 0x20;
                    if (revocation)
                        current->revoked = true;
                    if (binding && info.flags >= 0 && info.created >= current->flagsTime)
                    {
                        current->flags = info.flags;
                        current->flagsTime = info.created;
                    }
                    if (binding && info.hasExpiry && info.created >= current->expiryTime)
                    {
                        current->expiresAfter = info.expiresAfter;
                        current->expiryTime = info.created;
                    }
                    break;
                }
                default:
                    break;
                }
            }

            for (Packet& packet : packets)
                Wipe(packet.body);
            if (ring.keys.empty())
                throw Error("No PGP key was found in the pasted text");
            return ring;
        }

        bool Expired(const Key& key, uint32_t now)
        {
            return key.expiresAfter != 0 && uint64_t(key.created) + key.expiresAfter < now;
        }

        // picks which key to encrypt to. skips revoked/expired stuff and keys not flagged for encryption,
        // then takes the newest. same idea as gpg
        const Key& SelectRecipient(const Keyring& ring)
        {
            uint32_t now = static_cast<uint32_t>(std::time(nullptr));
            const Key& primary = ring.keys.front();
            if (primary.revoked)
                throw Error("The recipient's key has been revoked");
            if (Expired(primary, now))
                throw Error("The recipient's key has expired");

            const Key* best = nullptr;
            std::string problem;
            for (const Key& key : ring.keys)
            {
                if (key.revoked || Expired(key, now))
                    continue;
                if (key.flags >= 0 && !(key.flags & 0x0C))
                    continue;
                if (!key.problem.empty())
                {
                    problem = key.problem;
                    continue;
                }
                if (!key.supported)
                    continue;
                if (!best || key.created > best->created)
                    best = &key;
            }
            if (!best)
                throw Error(problem.empty() ? "The public key has no usable encryption key" : problem);
            return *best;
        }

        // rfc 6637 KDF: hash(00 00 00 01 || shared secret || params). the params include the recipient's
        // fingerprint so a wrapped key can't be replayed against some other key
        Bytes EcdhKek(const Key& key, const uint8_t* shared)
        {
            Bytes param;
            param.push_back(static_cast<uint8_t>(key.curveOid.size()));
            Append(param, key.curveOid);
            param.push_back(AlgorithmEcdh);
            Append(param, key.kdfParams);
            param.insert(param.end(), AnonymousSender, AnonymousSender + 20);
            Append(param, key.fingerprint);

            Hasher hasher(HashFromId(key.kdfHash));
            const uint8_t counter[4] = { 0, 0, 0, 1 };
            hasher.Update(counter, 4);
            hasher.Update(shared, 32);
            hasher.Update(param);
            Bytes kek = hasher.Finish();
            size_t length = CipherKeyLength(key.kdfCipher);
            if (kek.size() < length)
                throw Error("The key's KDF hash is too short for its wrapping cipher");
            kek.resize(length);
            return kek;
        }

        // yeah basically this shit wraps the random AES key for the recipient.
        // RSA just encrypts it, cv25519 does a throwaway ECDH and then AES key wrap
        Bytes BuildSessionKeyPacket(const Key& key, int cipher, const Bytes& sessionKey)
        {
            Bytes body;
            body.push_back(3);
            Append(body, key.keyId);
            body.push_back(static_cast<uint8_t>(key.algorithm));

            Bytes m;
            m.push_back(static_cast<uint8_t>(cipher));
            Append(m, sessionKey);
            uint16_t sum = Checksum(sessionKey.data(), sessionKey.size());
            m.push_back(static_cast<uint8_t>(sum >> 8));
            m.push_back(static_cast<uint8_t>(sum));

            if (IsRsa(key.algorithm))
            {
                WriteMpi(body, RsaEncrypt(key.rsaN, key.rsaE, m));
            }
            else
            {
                Bytes ephemeralSecret = RandomBytes(32);
                uint8_t ephemeralPublic[32];
                uint8_t shared[32];
                X25519Base(ephemeralPublic, ephemeralSecret.data());
                X25519(shared, ephemeralSecret.data(), key.ecPoint.data() + 1);
                Wipe(ephemeralSecret);
                uint8_t zero[32] = {};
                if (ConstantTimeEqual(shared, zero, 32))
                    throw Error("The recipient's Curve25519 key is invalid");

                Bytes kek = EcdhKek(key, shared);
                WipeMemory(shared, sizeof(shared));
                // PKCS5 padding up to a multiple of 8, key wrap only works on 8 byte blocks
                uint8_t pad = static_cast<uint8_t>(8 - m.size() % 8);
                m.insert(m.end(), pad, pad);
                Bytes wrapped = AesKeyWrap(kek, m);
                Wipe(kek);

                Bytes point;
                point.push_back(0x40);
                point.insert(point.end(), ephemeralPublic, ephemeralPublic + 32);
                WriteMpi(body, point);
                body.push_back(static_cast<uint8_t>(wrapped.size()));
                Append(body, wrapped);
            }
            Wipe(m);
            return body;
        }

        // decrypts the secret half of a key with the passphrase and pulls out the numbers we need.
        // throws PassphraseError so the UI can ask for it (Application.cpp line 332)
        void Unlock(Key& key, std::string_view passphrase)
        {
            if (key.unlocked)
                return;

            Bytes plain;
            if (key.protection == 0)
            {
                plain = key.secretData;
                if (plain.size() < 2 || Checksum(plain.data(), plain.size() - 2) != ((plain[plain.size() - 2] << 8) | plain.back()))
                    throw Error("The private key is corrupt");
                plain.resize(plain.size() - 2);
            }
            else
            {
                if (passphrase.empty())
                    throw PassphraseError("This private key is protected by a passphrase", true);
                Bytes derived = DeriveKey(key.s2k, passphrase, CipherKeyLength(key.protectionCipher));
                Aes aes(derived);
                Wipe(derived);
                plain = CfbDecrypt(aes, key.iv.data(), key.secretData.data(), key.secretData.size());
                if (key.protection == 254)
                {
                    if (plain.size() < 20)
                        throw PassphraseError("The passphrase is incorrect", false);
                    Bytes check(plain.begin(), plain.end() - 20);
                    Bytes digest = Hash(HashAlgorithm::Sha1, check);
                    Wipe(check);
                    if (!ConstantTimeEqual(digest.data(), plain.data() + plain.size() - 20, 20))
                    {
                        Wipe(plain);
                        throw PassphraseError("The passphrase is incorrect", false);
                    }
                    plain.resize(plain.size() - 20);
                }
                else
                {
                    if (plain.size() < 2 || Checksum(plain.data(), plain.size() - 2) != ((plain[plain.size() - 2] << 8) | plain.back()))
                    {
                        Wipe(plain);
                        throw PassphraseError("The passphrase is incorrect", false);
                    }
                    plain.resize(plain.size() - 2);
                }
            }

            try
            {
                Reader reader(plain);
                if (IsRsa(key.algorithm))
                {
                    Bytes d = reader.Mpi();
                    Wipe(d);
                    key.rsaP = reader.Mpi();
                    key.rsaQ = reader.Mpi();
                }
                else
                {
                    Bytes secret = PadLeft(reader.Mpi(), 32);
                    // gpg stores the cv25519 secret big endian but x25519 wants little endian, so flip it.
                    // then double check it actually gives the public key we already have
                    key.ecSecret.assign(secret.rbegin(), secret.rend());
                    Wipe(secret);
                    uint8_t derivedPublic[32];
                    X25519Base(derivedPublic, key.ecSecret.data());
                    if (!ConstantTimeEqual(derivedPublic, key.ecPoint.data() + 1, 32))
                    {
                        Wipe(key.ecSecret);
                        throw Error("The private key does not match its public key");
                    }
                }
            }
            catch (...)
            {
                Wipe(plain);
                throw;
            }
            Wipe(plain);
            key.unlocked = true;
        }

        // reverse of BuildSessionKeyPacket (line 1098), gets the AES key back out
        void DecryptSessionKey(const Key& key, const Bytes& fields, SessionKey& session)
        {
            Reader reader(fields);
            Bytes m;
            if (IsRsa(key.algorithm))
            {
                m = RsaDecrypt(key.rsaN, key.rsaE, key.rsaP, key.rsaQ, reader.Mpi());
            }
            else
            {
                Bytes point = reader.Mpi();
                if (point.size() != 33 || point[0] != 0x40)
                    throw Error("The message contains an invalid Curve25519 ephemeral key");
                Bytes wrapped = reader.Take(reader.Byte());
                uint8_t shared[32];
                X25519(shared, key.ecSecret.data(), point.data() + 1);
                Bytes kek = EcdhKek(key, shared);
                WipeMemory(shared, sizeof(shared));
                m = AesKeyUnwrap(kek, wrapped);
                Wipe(kek);
                uint8_t pad = m.empty() ? 0 : m.back();
                if (pad == 0 || pad > 8 || pad > m.size())
                {
                    Wipe(m);
                    throw Error("The session key padding is invalid");
                }
                for (size_t i = m.size() - pad; i < m.size(); ++i)
                {
                    if (m[i] != pad)
                    {
                        Wipe(m);
                        throw Error("The session key padding is invalid");
                    }
                }
                m.resize(m.size() - pad);
            }

            if (m.size() < 4)
            {
                Wipe(m);
                throw Error("The session key is invalid");
            }
            session.cipher = m[0];
            session.key.assign(m.begin() + 1, m.end() - 2);
            uint16_t expected = static_cast<uint16_t>((m[m.size() - 2] << 8) | m.back());
            Wipe(m);
            if (Checksum(session.key.data(), session.key.size()) != expected)
                throw Error("The session key checksum is invalid, the private key does not match this message");
            if (CipherKeyLength(session.cipher) != session.key.size())
                throw Error("The session key length is invalid");
        }

        // the normal encrypted packet (SEIPD v1). CFB decrypt, then check the SHA1 MDC on the end.
        // if the MDC doesn't match someone messed with the message and we refuse to show any of it
        Bytes DecryptIntegrityProtected(const Bytes& body, const SessionKey& session)
        {
            if (body.empty())
                throw Error("The encrypted data is empty");
            if (body[0] == 2)
                throw Error("Version 2 encrypted data packets (RFC 9580) are not supported");
            if (body[0] != 1)
                throw Error("Unsupported encrypted data packet version");

            Aes aes(session.key);
            uint8_t iv[BlockSize] = {};
            Bytes data = CfbDecrypt(aes, iv, body.data() + 1, body.size() - 1);
            if (data.size() < BlockSize + 2 + 22)
                throw Error("The encrypted data is truncated");
            // quick check: the last 2 bytes of the random prefix get repeated, cheap way to spot a wrong key early
            if (data[BlockSize - 2] != data[BlockSize] || data[BlockSize - 1] != data[BlockSize + 1])
                throw Error("Decryption failed, the session key is incorrect");

            size_t mdcStart = data.size() - 22;
            Bytes hashed(data.begin(), data.begin() + mdcStart + 2);
            Bytes digest = Hash(HashAlgorithm::Sha1, hashed);
            Wipe(hashed);
            if (data[mdcStart] != 0xD3 || data[mdcStart + 1] != 0x14 || !ConstantTimeEqual(digest.data(), data.data() + mdcStart + 2, 20))
            {
                Wipe(data);
                throw Error("The message failed its integrity check, it may have been tampered with");
            }

            Bytes plaintext(data.begin() + BlockSize + 2, data.begin() + mdcStart);
            Wipe(data);
            return plaintext;
        }

        // gpg's AEAD packet. the message is cut into chunks that each get their own tag,
        // then one final tag over the total length so nobody can chop chunks off the end
        Bytes DecryptOcb(const Bytes& body, const SessionKey& session)
        {
            Reader reader(body);
            uint8_t version = reader.Byte();
            uint8_t cipher = reader.Byte();
            uint8_t mode = reader.Byte();
            uint8_t chunkByte = reader.Byte();
            if (version != 1)
                throw Error("Unsupported AEAD packet version");
            if (mode != 2)
                throw Error("Only OCB mode AEAD messages are supported");
            if (chunkByte > 56)
                throw Error("The AEAD chunk size is invalid");
            if (CipherKeyLength(cipher) != session.key.size())
                throw Error("The session key does not match the message cipher");

            Bytes iv = reader.Take(15);
            Bytes rest = reader.Rest();
            if (rest.size() < BlockSize)
                throw Error("The encrypted data is truncated");

            Aes aes(session.key);
            Ocb ocb(aes);
            Bytes header = { 0xD4, version, cipher, mode, chunkByte };
            size_t chunkSize = size_t(1) << (chunkByte + 6);
            size_t contentEnd = rest.size() - BlockSize;
            size_t position = 0;
            uint64_t index = 0;
            Bytes out;

            auto nonceFor = [&](uint64_t chunk)
            {
                Bytes nonce = iv;
                for (int i = 0; i < 8; ++i)
                    // chunk index gets xored into the last 8 bytes of the IV
                    nonce[7 + i] ^= static_cast<uint8_t>(chunk >> (56 - 8 * i));
                return nonce;
            };

            while (position < contentEnd)
            {
                size_t length = std::min(chunkSize + BlockSize, contentEnd - position);
                if (length < BlockSize)
                    throw Error("The encrypted data is truncated");
                Bytes associated = header;
                AppendU64(associated, index);
                Append(out, ocb.Decrypt(nonceFor(index), associated, rest.data() + position, length - BlockSize, rest.data() + position + length - BlockSize));
                position += length;
                ++index;
            }

            Bytes associated = header;
            AppendU64(associated, index);
            AppendU64(associated, out.size());
            ocb.Decrypt(nonceFor(index), associated, nullptr, 0, rest.data() + contentEnd);
            return out;
        }

        // digs through the decrypted packets for the actual text. unzips if needed, skips signatures
        std::string ExtractLiteral(const Bytes& data, int depth)
        {
            if (depth > 4)
                throw Error("The message is nested too deeply");
            std::vector<Packet> packets = ReadPackets(data.data(), data.size());
            for (const Packet& packet : packets)
            {
                if (packet.tag == TagCompressed)
                {
                    Reader reader(packet.body);
                    int algorithm = reader.Byte();
                    Bytes compressed = reader.Rest();
                    switch (algorithm)
                    {
                    case 0: return ExtractLiteral(compressed, depth + 1);
                    case 1: return ExtractLiteral(Inflate(compressed.data(), compressed.size()), depth + 1);
                    case 2: return ExtractLiteral(InflateZlib(compressed.data(), compressed.size()), depth + 1);
                    case 3: throw Error("BZip2 compressed messages are not supported");
                    default: throw Error("The message uses an unknown compression algorithm");
                    }
                }
                if (packet.tag == TagLiteral)
                {
                    Reader reader(packet.body);
                    reader.Byte();
                    reader.Skip(reader.Byte());
                    reader.Skip(4);
                    Bytes content = reader.Rest();
                    std::string text(content.begin(), content.end());
                    Wipe(content);
                    return text;
                }
            }
            throw Error("The decrypted message contained no readable data");
        }
    }

    // the Encrypt button ends up here (Application.cpp line 437).
    // random AES-256 key -> wrap it for the recipient -> encrypt literal packet + MDC with it -> armor
    EncryptResult EncryptMessage(std::string_view message, std::string_view publicKey)
    {
        if (message.empty())
            throw Error("Enter a message to encrypt");
        if (IsBlank(publicKey))
            throw Error("Paste the recipient's public key");

        Keyring ring = ParseKeyring(publicKey);
        const Key& recipient = SelectRecipient(ring);

        SessionKey session;
        session.cipher = CipherAes256;
        session.key = RandomBytes(CipherKeyLength(session.cipher));

        Bytes literal;
        // 'b' = binary, so line endings come out exactly how they went in
        literal.push_back('b');
        literal.push_back(0);
        AppendU32(literal, static_cast<uint32_t>(std::time(nullptr)));
        literal.insert(literal.end(), message.begin(), message.end());

        Bytes inner = RandomBytes(BlockSize);
        // repeat the last 2 prefix bytes, that's the quick check DecryptIntegrityProtected looks for
        inner.push_back(inner[BlockSize - 2]);
        inner.push_back(inner[BlockSize - 1]);
        WritePacket(inner, TagLiteral, literal);
        Wipe(literal);
        inner.push_back(0xD3);
        inner.push_back(0x14);
        Append(inner, Hash(HashAlgorithm::Sha1, inner));

        Aes aes(session.key);
        uint8_t iv[BlockSize] = {};
        Bytes encrypted;
        encrypted.push_back(1);
        Append(encrypted, CfbEncrypt(aes, iv, inner));
        Wipe(inner);

        Bytes output;
        WritePacket(output, TagSessionKey, BuildSessionKeyPacket(recipient, session.cipher, session.key));
        WritePacket(output, TagIntegrityProtected, encrypted);

        EncryptResult result;
        result.message = Armor(output, "PGP MESSAGE");
        result.recipient = ring.userId;
        result.keyId = Hex(recipient.keyId);
        return result;
    }

    // the Decrypt button ends up here. find a session key packet meant for one of our keys,
    // unlock that key, get the session key out, decrypt, done. tries every match before giving up
    DecryptResult DecryptMessage(std::string_view message, std::string_view privateKey, std::string_view passphrase)
    {
        if (IsBlank(message))
            throw Error("Paste the encrypted PGP message");
        if (IsBlank(privateKey))
            throw Error("Paste your private PGP key");

        std::string type;
        Bytes data = Dearmor(message, type);
        if (type.find("KEY") != std::string::npos)
            throw Error("A PGP key was pasted where the encrypted message was expected");

        Keyring ring = ParseKeyring(privateKey);
        if (std::none_of(ring.keys.begin(), ring.keys.end(), [](const Key& key) { return key.secret; }))
            throw Error("That is a public key, paste the private key block (BEGIN PGP PRIVATE KEY BLOCK)");

        std::vector<Packet> packets = ReadPackets(data.data(), data.size());
        std::vector<const Packet*> sessions;
        const Packet* encrypted = nullptr;
        for (const Packet& packet : packets)
        {
            if (packet.tag == TagSessionKey)
                sessions.push_back(&packet);
            else if (!encrypted && (packet.tag == TagIntegrityProtected || packet.tag == TagOcbEncrypted || packet.tag == TagSymmetricEncrypted))
                encrypted = &packet;
        }

        if (!encrypted)
            throw Error("No encrypted data was found in the message");
        if (encrypted->tag == TagSymmetricEncrypted)
            throw Error("The message has no integrity protection and was rejected");
        if (sessions.empty())
            throw Error("The message was not encrypted to a public key, it may be password encrypted");

        bool matched = false;
        std::string lastError;
        for (const Packet* sessionPacket : sessions)
        {
            Reader reader(sessionPacket->body);
            int version = reader.Byte();
            if (version != 3)
            {
                lastError = "Version " + std::to_string(version) + " session key packets are not supported";
                continue;
            }
            Bytes keyId = reader.Take(8);
            int algorithm = reader.Byte();
            Bytes fields = reader.Rest();
            // all zero key id = the sender hid who it's for (gpg --throw-keyids), so just try every key we have
            bool wildcard = std::all_of(keyId.begin(), keyId.end(), [](uint8_t b) { return b == 0; });

            for (Key& key : ring.keys)
            {
                if (!key.secret || key.keyId.empty())
                    continue;
                if (!wildcard && keyId != key.keyId)
                    continue;
                if (!(IsRsa(algorithm) && IsRsa(key.algorithm)) && algorithm != key.algorithm)
                    continue;

                matched = true;
                if (!key.problem.empty())
                {
                    lastError = key.problem;
                    continue;
                }
                if (!key.supported)
                {
                    lastError = "The matching private key uses an unsupported algorithm";
                    continue;
                }
                if (key.s2k.dummy)
                {
                    lastError = "The matching private key has no secret part, it may be stored on a smartcard";
                    continue;
                }

                try
                {
                    Unlock(key, passphrase);
                    SessionKey session;
                    DecryptSessionKey(key, fields, session);
                    Bytes plaintext = encrypted->tag == TagOcbEncrypted ? DecryptOcb(encrypted->body, session) : DecryptIntegrityProtected(encrypted->body, session);
                    std::string text = ExtractLiteral(plaintext, 0);
                    Wipe(plaintext);

                    DecryptResult result;
                    result.keyId = Hex(key.keyId);
                    result.message.reserve(text.size());
                    for (size_t i = 0; i < text.size(); ++i)
                    {
                        if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n')
                            continue;
                        result.message += text[i];
                    }
                    Wipe(text);
                    return result;
                }
                // passphrase problems go straight up to the UI, anything else we remember and move on to the next key
                catch (const PassphraseError&)
                {
                    throw;
                }
                catch (const Error& error)
                {
                    lastError = error.what();
                }
            }
        }

        if (!matched)
            throw Error("This message was not encrypted to the supplied private key");
        throw Error(lastError.empty() ? "The message could not be decrypted" : lastError);
    }

    // lightweight ParseKeyring for the My PGP tab, just says what kind of key got pasted
    KeyInfo InspectKey(std::string_view armored)
    {
        if (IsBlank(armored))
            throw Error("No key was entered");
        Keyring ring = ParseKeyring(armored);
        KeyInfo info;
        info.secret = std::any_of(ring.keys.begin(), ring.keys.end(), [](const Key& key) { return key.secret; });
        info.userId = ring.userId;
        info.keyId = Hex(ring.keys.front().keyId);
        return info;
    }
}
