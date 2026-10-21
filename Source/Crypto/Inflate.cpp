#include "Inflate.h"

#include <array>

namespace Pgp
{
    namespace
    {
        // cap at 256mb so nobody can send a zip bomb and eat all your ram
        constexpr size_t MaximumOutput = size_t(256) * 1024 * 1024;

        const short LengthBase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
        const short LengthExtra[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
        const short DistanceBase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
        const short DistanceExtra[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
        const short CodeLengthOrder[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };

        // deflate reads bits LSB first, this just pulls them out of the byte stream
        struct BitReader
        {
            const uint8_t* data = nullptr;
            size_t size = 0;
            size_t position = 0;
            uint32_t buffer = 0;
            int count = 0;

            int Bits(int need)
            {
                uint32_t value = buffer;
                while (count < need)
                {
                    if (position >= size)
                        throw Error("Compressed data is truncated");
                    value |= uint32_t(data[position++]) << count;
                    count += 8;
                }
                buffer = value >> need;
                count -= need;
                return static_cast<int>(value & ((1u << need) - 1));
            }
        };

        struct Huffman
        {
            std::array<short, 16> count{};
            std::array<short, 320> symbol{};
        };

        // builds a canonical huffman table from the code lengths, same trick zlib's puff.c uses
        int Build(Huffman& table, const short* lengths, int n)
        {
            table.count.fill(0);
            for (int i = 0; i < n; ++i)
                ++table.count[lengths[i]];
            if (table.count[0] == n)
                return 0;

            int left = 1;
            for (int length = 1; length < 16; ++length)
            {
                left <<= 1;
                left -= table.count[length];
                if (left < 0)
                    return left;
            }

            short offsets[16] = {};
            for (int length = 1; length < 15; ++length)
                offsets[length + 1] = static_cast<short>(offsets[length] + table.count[length]);
            for (int symbol = 0; symbol < n; ++symbol)
                if (lengths[symbol] != 0)
                    table.symbol[offsets[lengths[symbol]]++] = static_cast<short>(symbol);
            return left;
        }

        int Decode(BitReader& reader, const Huffman& table)
        {
            int code = 0;
            int first = 0;
            int index = 0;
            for (int length = 1; length < 16; ++length)
            {
                code |= reader.Bits(1);
                int count = table.count[length];
                if (code - count < first)
                    return table.symbol[index + (code - first)];
                index += count;
                first += count;
                first <<= 1;
                code <<= 1;
            }
            throw Error("Compressed data is corrupt");
        }

        void Codes(BitReader& reader, Bytes& output, const Huffman& lengthCode, const Huffman& distanceCode)
        {
            for (;;)
            {
                int symbol = Decode(reader, lengthCode);
                if (symbol < 256)
                {
                    output.push_back(static_cast<uint8_t>(symbol));
                }
                else if (symbol == 256)
                {
                    return;
                }
                else
                {
                    symbol -= 257;
                    if (symbol >= 29)
                        throw Error("Compressed data is corrupt");
                    size_t length = LengthBase[symbol] + reader.Bits(LengthExtra[symbol]);
                    int distanceSymbol = Decode(reader, distanceCode);
                    if (distanceSymbol >= 30)
                        throw Error("Compressed data is corrupt");
                    size_t distance = DistanceBase[distanceSymbol] + reader.Bits(DistanceExtra[distanceSymbol]);
                    if (distance > output.size())
                        throw Error("Compressed data is corrupt");
                    size_t from = output.size() - distance;
                    for (size_t i = 0; i < length; ++i)
                        output.push_back(output[from + i]);
                }
                if (output.size() > MaximumOutput)
                    throw Error("Decompressed message is too large");
            }
        }

        // block type 0, not compressed at all. LEN, its inverse, then raw bytes
        void Stored(BitReader& reader, Bytes& output)
        {
            reader.buffer = 0;
            reader.count = 0;
            if (reader.position + 4 > reader.size)
                throw Error("Compressed data is truncated");
            size_t length = reader.data[reader.position] | (size_t(reader.data[reader.position + 1]) << 8);
            size_t inverse = reader.data[reader.position + 2] | (size_t(reader.data[reader.position + 3]) << 8);
            reader.position += 4;
            if (length != (~inverse & 0xFFFF))
                throw Error("Compressed data is corrupt");
            if (reader.position + length > reader.size)
                throw Error("Compressed data is truncated");
            output.insert(output.end(), reader.data + reader.position, reader.data + reader.position + length);
            reader.position += length;
            if (output.size() > MaximumOutput)
                throw Error("Decompressed message is too large");
        }

        // block type 1, the hardcoded tables from the deflate spec. built once and reused
        void Fixed(BitReader& reader, Bytes& output)
        {
            static Huffman lengthCode;
            static Huffman distanceCode;
            static bool built = [&]
            {
                short lengths[288];
                int symbol = 0;
                for (; symbol < 144; ++symbol)
                    lengths[symbol] = 8;
                for (; symbol < 256; ++symbol)
                    lengths[symbol] = 9;
                for (; symbol < 280; ++symbol)
                    lengths[symbol] = 7;
                for (; symbol < 288; ++symbol)
                    lengths[symbol] = 8;
                Build(lengthCode, lengths, 288);
                for (symbol = 0; symbol < 30; ++symbol)
                    lengths[symbol] = 5;
                Build(distanceCode, lengths, 30);
                return true;
            }();
            (void)built;
            Codes(reader, output, lengthCode, distanceCode);
        }

        // block type 2, the tables come in the stream itself, compressed with ANOTHER huffman table (yes really)
        void Dynamic(BitReader& reader, Bytes& output)
        {
            int lengthCount = reader.Bits(5) + 257;
            int distanceCount = reader.Bits(5) + 1;
            int codeCount = reader.Bits(4) + 4;
            if (lengthCount > 286 || distanceCount > 30)
                throw Error("Compressed data is corrupt");

            short lengths[320] = {};
            for (int index = 0; index < codeCount; ++index)
                lengths[CodeLengthOrder[index]] = static_cast<short>(reader.Bits(3));

            Huffman lengthCode;
            Huffman distanceCode;
            if (Build(lengthCode, lengths, 19) != 0)
                throw Error("Compressed data is corrupt");

            int index = 0;
            while (index < lengthCount + distanceCount)
            {
                int symbol = Decode(reader, lengthCode);
                if (symbol < 16)
                {
                    lengths[index++] = static_cast<short>(symbol);
                    continue;
                }
                short value = 0;
                int repeat = 0;
                if (symbol == 16)
                {
                    if (index == 0)
                        throw Error("Compressed data is corrupt");
                    value = lengths[index - 1];
                    repeat = 3 + reader.Bits(2);
                }
                else if (symbol == 17)
                {
                    repeat = 3 + reader.Bits(3);
                }
                else
                {
                    repeat = 11 + reader.Bits(7);
                }
                if (index + repeat > lengthCount + distanceCount)
                    throw Error("Compressed data is corrupt");
                while (repeat--)
                    lengths[index++] = value;
            }

            if (lengths[256] == 0)
                throw Error("Compressed data is corrupt");
            if (Build(lengthCode, lengths, lengthCount) < 0)
                throw Error("Compressed data is corrupt");
            if (Build(distanceCode, lengths + lengthCount, distanceCount) < 0)
                throw Error("Compressed data is corrupt");
            Codes(reader, output, lengthCode, distanceCode);
        }
    }

    Bytes Inflate(const uint8_t* data, size_t size)
    {
        BitReader reader;
        reader.data = data;
        reader.size = size;
        Bytes output;
        int last = 0;
        do
        {
            last = reader.Bits(1);
            int type = reader.Bits(2);
            if (type == 0)
                Stored(reader, output);
            else if (type == 1)
                Fixed(reader, output);
            else if (type == 2)
                Dynamic(reader, output);
            else
                throw Error("Compressed data is corrupt");
        } while (!last);
        return output;
    }

    // zlib is just deflate with a 2 byte header and adler32 on the end. we check the header and skip the checksum,
    // the MDC/OCB tag already covers the whole thing anyway
    Bytes InflateZlib(const uint8_t* data, size_t size)
    {
        if (size < 2)
            throw Error("Compressed data is truncated");
        if ((data[0] & 0x0F) != 8 || ((data[0] << 8) | data[1]) % 31 != 0 || (data[1] & 0x20))
            throw Error("Unsupported ZLIB stream");
        return Inflate(data + 2, size - 2);
    }
}
