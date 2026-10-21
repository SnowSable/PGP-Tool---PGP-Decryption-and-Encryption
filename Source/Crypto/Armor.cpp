#include "Armor.h"


namespace Pgp
{
    namespace
    {
        const char Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        // the =XXXX line at the bottom of armored blocks, crc24 straight out of rfc 4880
        uint32_t Crc24(const Bytes& data)
        {
            uint32_t crc = 0xB704CE;
            for (uint8_t byte : data)
            {
                crc ^= uint32_t(byte) << 16;
                for (int i = 0; i < 8; ++i)
                {
                    crc <<= 1;
                    if (crc & 0x1000000)
                        crc ^= 0x1864CFB;
                }
            }
            return crc & 0xFFFFFF;
        }

        std::string Base64Encode(const Bytes& data)
        {
            std::string out;
            out.reserve((data.size() + 2) / 3 * 4);
            size_t i = 0;
            for (; i + 2 < data.size(); i += 3)
            {
                uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
                out += Alphabet[(v >> 18) & 63];
                out += Alphabet[(v >> 12) & 63];
                out += Alphabet[(v >> 6) & 63];
                out += Alphabet[v & 63];
            }
            if (i + 1 == data.size())
            {
                uint32_t v = uint32_t(data[i]) << 16;
                out += Alphabet[(v >> 18) & 63];
                out += Alphabet[(v >> 12) & 63];
                out += "==";
            }
            else if (i + 2 == data.size())
            {
                uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
                out += Alphabet[(v >> 18) & 63];
                out += Alphabet[(v >> 12) & 63];
                out += Alphabet[(v >> 6) & 63];
                out += '=';
            }
            return out;
        }

        int Base64Value(char c)
        {
            if (c >= 'A' && c <= 'Z')
                return c - 'A';
            if (c >= 'a' && c <= 'z')
                return c - 'a' + 26;
            if (c >= '0' && c <= '9')
                return c - '0' + 52;
            if (c == '+')
                return 62;
            if (c == '/')
                return 63;
            return -1;
        }

        Bytes Base64Decode(std::string_view text)
        {
            Bytes out;
            uint32_t buffer = 0;
            int bits = 0;
            for (char c : text)
            {
                if (c == '=')
                    break;
                int value = Base64Value(c);
                if (value < 0)
                {
                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                        continue;
                    throw Error("The PGP block contains invalid characters");
                }
                buffer = (buffer << 6) | uint32_t(value);
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
                }
            }
            return out;
        }

        std::string_view Trim(std::string_view text)
        {
            size_t start = text.find_first_not_of(" \t\r\n");
            if (start == std::string_view::npos)
                return {};
            size_t end = text.find_last_not_of(" \t\r\n");
            return text.substr(start, end - start + 1);
        }

        // walks the text a line at a time without copying it, trims spaces and \r so windows line endings don't matter
        bool NextLine(std::string_view& text, std::string_view& line)
        {
            if (text.empty())
                return false;
            size_t end = text.find('\n');
            line = Trim(text.substr(0, end));
            text = end == std::string_view::npos ? std::string_view() : text.substr(end + 1);
            return true;
        }
    }

    // wraps binary in the -----BEGIN PGP----- base64 thing, 64 chars a line like gpg does
    std::string Armor(const Bytes& data, const std::string& type, const std::string& comment)
    {
        std::string encoded = Base64Encode(data);
        std::string out = "-----BEGIN " + type + "-----\n";
        if (!comment.empty())
            out += "Comment: " + comment + "\n";
        out += "\n";
        for (size_t i = 0; i < encoded.size(); i += 64)
            out += encoded.substr(i, 64) + "\n";
        uint32_t crc = Crc24(data);
        Bytes crcBytes = { static_cast<uint8_t>(crc >> 16), static_cast<uint8_t>(crc >> 8), static_cast<uint8_t>(crc) };
        out += "=" + Base64Encode(crcBytes) + "\n";
        out += "-----END " + type + "-----\n";
        return out;
    }

    // yeah basically this finds the BEGIN line, skips headers like Version: and Comment:,
    // glues the base64 back together and checks the crc if there is one.
    // anything before BEGIN or after END gets ignored so people can paste a whole email in
    Bytes Dearmor(std::string_view text, std::string& type)
    {
        std::string_view line;
        bool inBlock = false;
        bool inBody = false;
        std::string body;
        std::string_view checksum;

        while (NextLine(text, line))
        {
            if (!inBlock)
            {
                if (line.starts_with("-----BEGIN PGP ") && line.size() > 16 && line.ends_with("-----"))
                {
                    type = std::string(line.substr(11, line.size() - 16));
                    inBlock = true;
                }
                continue;
            }

            if (line.starts_with("-----END "))
            {
                if (body.empty())
                    throw Error("The PGP block is empty");
                Bytes data;
                try
                {
                    // body could be a whole private key in base64, it gets scrubbed right after this
                    data = Base64Decode(body);
                }
                catch (...)
                {
                    Wipe(body);
                    throw;
                }
                Wipe(body);
                if (!checksum.empty())
                {
                    Bytes expected = Base64Decode(checksum);
                    uint32_t crc = Crc24(data);
                    if (expected.size() != 3 || expected[0] != ((crc >> 16) & 0xFF) || expected[1] != ((crc >> 8) & 0xFF) || expected[2] != (crc & 0xFF))
                    {
                        Wipe(data);
                        throw Error("The PGP block checksum is invalid, it may have been copied incorrectly");
                    }
                }
                return data;
            }

            if (!inBody)
            {
                // header lines always have a colon and base64 never does, that's how we tell them apart
                if (line.empty() || line.find(':') != std::string_view::npos)
                    continue;
                inBody = true;
            }

            if (line.empty())
                continue;
            if (line[0] == '=' && line.size() == 5)
            {
                checksum = line.substr(1);
                continue;
            }
            body += line;
        }

        Wipe(body);
        if (inBlock)
            throw Error("The PGP block is missing its END line");
        throw Error("No PGP block was found, paste the full text including the BEGIN and END lines");
    }
}
