#include "Curve25519.h"

#include <cstring>

namespace Pgp
{
    namespace
    {
        // this whole file is the curve25519 math from tweetnacl, just renamed so it reads like normal code.
        // a field element is 16 limbs of 16 bits, int64 so multiplying doesn't overflow
        using Field = int64_t[16];

        const Field Constant121665 = { 0xDB41, 1 };

        // pushes the overflow from each limb into the next one. the top limb wraps back into limb 0 times 38
        // because 2^256 is 38 mod p
        void Carry(Field o)
        {
            for (int i = 0; i < 16; ++i)
            {
                o[i] += (int64_t(1) << 16);
                int64_t c = o[i] >> 16;
                o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
                o[i] -= c * 65536;
            }
        }

        // constant time swap, no ifs, so the timing doesn't leak key bits
        void Select(Field p, Field q, int64_t bit)
        {
            int64_t mask = ~(bit - 1);
            for (int i = 0; i < 16; ++i)
            {
                int64_t t = mask & (p[i] ^ q[i]);
                p[i] ^= t;
                q[i] ^= t;
            }
        }

        // squashes a field element down to 32 little endian bytes, fully reduced mod p first
        void Pack(uint8_t* out, const Field n)
        {
            Field m;
            Field t;
            for (int i = 0; i < 16; ++i)
                t[i] = n[i];
            Carry(t);
            Carry(t);
            Carry(t);
            for (int j = 0; j < 2; ++j)
            {
                m[0] = t[0] - 0xFFED;
                for (int i = 1; i < 15; ++i)
                {
                    m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
                    m[i - 1] &= 0xFFFF;
                }
                m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
                int64_t b = (m[15] >> 16) & 1;
                m[14] &= 0xFFFF;
                Select(t, m, 1 - b);
            }
            for (int i = 0; i < 16; ++i)
            {
                out[2 * i] = static_cast<uint8_t>(t[i] & 0xFF);
                out[2 * i + 1] = static_cast<uint8_t>(t[i] >> 8);
            }
        }

        void Unpack(Field o, const uint8_t* n)
        {
            for (int i = 0; i < 16; ++i)
                o[i] = n[2 * i] + (int64_t(n[2 * i + 1]) << 8);
            o[15] &= 0x7FFF;
        }

        void Add(Field o, const Field a, const Field b)
        {
            for (int i = 0; i < 16; ++i)
                o[i] = a[i] + b[i];
        }

        void Subtract(Field o, const Field a, const Field b)
        {
            for (int i = 0; i < 16; ++i)
                o[i] = a[i] - b[i];
        }

        void Multiply(Field o, const Field a, const Field b)
        {
            int64_t t[31] = {};
            for (int i = 0; i < 16; ++i)
                for (int j = 0; j < 16; ++j)
                    t[i + j] += a[i] * b[j];
            for (int i = 0; i < 15; ++i)
                t[i] += 38 * t[i + 16];
            for (int i = 0; i < 16; ++i)
                o[i] = t[i];
            Carry(o);
            Carry(o);
        }

        void Square(Field o, const Field a)
        {
            Multiply(o, a, a);
        }

        // inverse via fermat, x^(p-2). the a != 2 && a != 4 thing is just the bit pattern of p-2
        void Invert(Field o, const Field input)
        {
            Field c;
            for (int a = 0; a < 16; ++a)
                c[a] = input[a];
            for (int a = 253; a >= 0; --a)
            {
                Square(c, c);
                if (a != 2 && a != 4)
                    Multiply(c, c, input);
            }
            for (int a = 0; a < 16; ++a)
                o[a] = c[a];
        }
    }

    // the actual montgomery ladder, scalar gets clamped like rfc 7748 says.
    // checked against the test vectors in rfc 7748 section 5.2
    void X25519(uint8_t output[32], const uint8_t scalar[32], const uint8_t point[32])
    {
        uint8_t z[32];
        std::memcpy(z, scalar, 32);
        z[31] = static_cast<uint8_t>((z[31] & 127) | 64);
        z[0] &= 248;

        Field x;
        Field a = {};
        Field b;
        Field c = {};
        Field d = {};
        Field e;
        Field f;
        Unpack(x, point);
        for (int i = 0; i < 16; ++i)
            b[i] = x[i];
        a[0] = 1;
        d[0] = 1;

        for (int i = 254; i >= 0; --i)
        {
            int64_t r = (z[i >> 3] >> (i & 7)) & 1;
            Select(a, b, r);
            Select(c, d, r);
            Add(e, a, c);
            Subtract(a, a, c);
            Add(c, b, d);
            Subtract(b, b, d);
            Square(d, e);
            Square(f, a);
            Multiply(a, c, a);
            Multiply(c, b, e);
            Add(e, a, c);
            Subtract(a, a, c);
            Square(b, a);
            Subtract(c, d, f);
            Multiply(a, c, Constant121665);
            Add(a, a, d);
            // this was c*f in the first draft and broke everything lol, the rfc test vectors caught it
            Multiply(c, c, a);
            Multiply(a, d, f);
            Multiply(d, b, x);
            Square(b, e);
            Select(a, b, r);
            Select(c, d, r);
        }

        Invert(c, c);
        Multiply(a, a, c);
        Pack(output, a);
        std::memset(z, 0, sizeof(z));
    }

    void X25519Base(uint8_t output[32], const uint8_t scalar[32])
    {
        uint8_t basePoint[32] = { 9 };
        X25519(output, scalar, basePoint);
    }
}
