#include "Curve25519.h"
#include "Fixtures.h"
#include "OpenPgp.h"

#include <cstdio>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    class Failure : public std::exception
    {
    public:
        explicit Failure(std::string message) : message(std::move(message)) {}
        const char* what() const noexcept override { return message.c_str(); }

    private:
        std::string message;
    };

    void Expect(bool condition, const std::string& description)
    {
        if (!condition)
            throw Failure(description);
    }

    void ExpectEqual(std::string_view actual, std::string_view expected, const std::string& description)
    {
        if (actual != expected)
            throw Failure(description + " (got " + std::to_string(actual.size()) + " bytes, expected " + std::to_string(expected.size()) + ")");
    }

    std::string ExpectError(const std::function<void()>& action, std::string_view fragment)
    {
        try
        {
            action();
        }
        catch (const Pgp::Error& error)
        {
            std::string message = error.what();
            Expect(message.find(fragment) != std::string::npos, "error \"" + message + "\" does not mention \"" + std::string(fragment) + "\"");
            return message;
        }
        throw Failure("expected an error mentioning \"" + std::string(fragment) + "\"");
    }

    Pgp::Bytes FromHex(std::string_view hex)
    {
        Pgp::Bytes out;
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
            out.push_back(static_cast<uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
        return out;
    }

    void X25519Vector(std::string_view scalar, std::string_view point, std::string_view expected)
    {
        Pgp::Bytes k = FromHex(scalar);
        Pgp::Bytes u = FromHex(point);
        uint8_t out[32];
        Pgp::X25519(out, k.data(), u.data());
        Expect(Pgp::Bytes(out, out + 32) == FromHex(expected), "X25519 output does not match RFC 7748");
    }

    std::string Decrypt(std::string_view message, std::string_view key, std::string_view passphrase = {})
    {
        return Pgp::DecryptMessage(message, key, passphrase).message;
    }

    // makes armor look like it got copied out of an email: junk around it, indented, windows line endings
    std::string Mangle(std::string_view armored)
    {
        std::string out = "Here is the message you asked for:\r\n\r\n";
        size_t start = 0;
        while (start < armored.size())
        {
            size_t end = armored.find('\n', start);
            std::string_view line = armored.substr(start, end - start);
            if (!line.empty())
                out += "    " + std::string(line) + "\r\n";
            if (end == std::string_view::npos)
                break;
            start = end + 1;
        }
        out += "\r\nThanks\r\n";
        return out;
    }

    struct Test
    {
        const char* name;
        std::function<void()> run;
    };

    // fixtures come from GenerateFixtures.sh, which makes real gpg keys + messages and dumps them into Fixtures.h
    const std::vector<Test> Tests = {
        { "X25519 matches RFC 7748 vectors", []
            {
                X25519Vector("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
                X25519Vector("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d", "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
            } },
        { "Round trip with Curve25519 key", []
            {
                std::string armored = Pgp::EncryptMessage(Fixtures::SampleText, Fixtures::AlicePublic).message;
                ExpectEqual(Decrypt(armored, Fixtures::AliceSecret, Fixtures::AlicePassphrase), Fixtures::SampleText, "decrypted text differs");
            } },
        { "Round trip with RSA key", []
            {
                std::string armored = Pgp::EncryptMessage(Fixtures::MediumText, Fixtures::BobPublic).message;
                ExpectEqual(Decrypt(armored, Fixtures::BobSecret, Fixtures::BobPassphrase), Fixtures::MediumText, "decrypted text differs");
            } },
        { "Round trip with unprotected key", []
            {
                std::string armored = Pgp::EncryptMessage(Fixtures::SampleText, Fixtures::CarolPublic).message;
                ExpectEqual(Decrypt(armored, Fixtures::CarolSecret), Fixtures::SampleText, "decrypted text differs");
            } },
        { "Encrypt reports the recipient", []
            {
                Pgp::EncryptResult result = Pgp::EncryptMessage("x", Fixtures::AlicePublic);
                ExpectEqual(result.recipient, "Alice <alice@example.com>", "recipient user ID");
                Expect(result.keyId.size() == 16, "key ID is 16 hex digits");
            } },
        { "GnuPG ZLIB message", []
            {
                ExpectEqual(Decrypt(Fixtures::AliceDefault, Fixtures::AliceSecret, Fixtures::AlicePassphrase), Fixtures::SampleText, "decrypted text differs");
            } },
        { "GnuPG chunked OCB message", []
            {
                ExpectEqual(Decrypt(Fixtures::AliceOcb, Fixtures::AliceSecret, Fixtures::AlicePassphrase), Fixtures::MediumText, "decrypted text differs");
            } },
        { "GnuPG signed and encrypted message", []
            {
                ExpectEqual(Decrypt(Fixtures::AliceSigned, Fixtures::AliceSecret, Fixtures::AlicePassphrase), Fixtures::SampleText, "decrypted text differs");
            } },
        { "GnuPG ZIP message to RSA key", []
            {
                ExpectEqual(Decrypt(Fixtures::BobZip, Fixtures::BobSecret, Fixtures::BobPassphrase), Fixtures::SampleText, "decrypted text differs");
            } },
        { "GnuPG hidden recipient message", []
            {
                ExpectEqual(Decrypt(Fixtures::BobHidden, Fixtures::BobSecret, Fixtures::BobPassphrase), Fixtures::SampleText, "decrypted text differs");
            } },
        { "GnuPG uncompressed message", []
            {
                ExpectEqual(Decrypt(Fixtures::CarolPlain, Fixtures::CarolSecret), Fixtures::SampleText, "decrypted text differs");
            } },
        { "Pasted armor with surrounding text and CRLF", []
            {
                ExpectEqual(Decrypt(Mangle(Fixtures::CarolPlain), Mangle(Fixtures::CarolSecret)), Fixtures::SampleText, "decrypted text differs");
            } },
        { "Missing passphrase is reported", []
            {
                try
                {
                    Decrypt(Fixtures::AliceDefault, Fixtures::AliceSecret);
                }
                catch (const Pgp::PassphraseError& error)
                {
                    Expect(error.Missing(), "error should report a missing passphrase");
                    return;
                }
                throw Failure("expected a passphrase error");
            } },
        { "Wrong passphrase is reported", []
            {
                try
                {
                    Decrypt(Fixtures::AliceDefault, Fixtures::AliceSecret, "wrong");
                }
                catch (const Pgp::PassphraseError& error)
                {
                    Expect(!error.Missing(), "error should report a wrong passphrase");
                    return;
                }
                throw Failure("expected a passphrase error");
            } },
        // that fixture has one bit flipped near the end, right inside the MDC hash
        { "Tampered message is rejected", []
            {
                ExpectError([] { Decrypt(Fixtures::CarolTampered, Fixtures::CarolSecret); }, "integrity");
            } },
        { "BZip2 message is refused clearly", []
            {
                ExpectError([] { Decrypt(Fixtures::CarolBzip2, Fixtures::CarolSecret); }, "BZip2");
            } },
        { "Message for another key is refused", []
            {
                ExpectError([] { Decrypt(Fixtures::CarolPlain, Fixtures::AliceSecret, Fixtures::AlicePassphrase); }, "not encrypted to the supplied private key");
            } },
        { "Public key in the private key box is refused", []
            {
                ExpectError([] { Decrypt(Fixtures::CarolPlain, Fixtures::CarolPublic); }, "public key");
            } },
        { "Key in the message box is refused", []
            {
                ExpectError([] { Decrypt(Fixtures::CarolSecret, Fixtures::CarolSecret); }, "key was pasted");
            } },
        { "Message in the public key box is refused", []
            {
                ExpectError([] { Pgp::EncryptMessage("x", Fixtures::CarolPlain); }, "message was pasted");
            } },
        { "Signing only key is refused for encryption", []
            {
                ExpectError([] { Pgp::EncryptMessage("x", Fixtures::DavePublic); }, "no usable encryption key");
            } },
        { "Empty message is refused", []
            {
                ExpectError([] { Pgp::EncryptMessage("", Fixtures::AlicePublic); }, "Enter a message");
            } },
        { "Text without armor is refused", []
            {
                ExpectError([] { Pgp::EncryptMessage("x", "not a key"); }, "No PGP block");
            } },
        { "Inspect identifies secret and public blocks", []
            {
                Pgp::KeyInfo secret = Pgp::InspectKey(Fixtures::AliceSecret);
                Pgp::KeyInfo pub = Pgp::InspectKey(Fixtures::AlicePublic);
                Expect(secret.secret, "secret block should be secret");
                Expect(!pub.secret, "public block should not be secret");
                ExpectEqual(secret.keyId, pub.keyId, "both blocks share a primary key ID");
                ExpectEqual(pub.userId, "Alice <alice@example.com>", "user ID");
                Expect(Pgp::InspectKey(Fixtures::BobPublic).keyId != pub.keyId, "different keys have different IDs");
            } },
    };
}

int main()
{
    int failures = 0;
    for (const Test& test : Tests)
    {
        try
        {
            test.run();
            std::printf("PASS  %s\n", test.name);
        }
        catch (const std::exception& error)
        {
            ++failures;
            std::printf("FAIL  %s: %s\n", test.name, error.what());
        }
    }
    std::printf("\n%zu tests, %d failed\n", Tests.size(), failures);
    return failures == 0 ? 0 : 1;
}
