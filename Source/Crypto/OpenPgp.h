#pragma once

#include "Primitives.h"

#include <string_view>

namespace Pgp
{
    // its own type so the UI knows to pop up the passphrase box instead of just showing an error
    class PassphraseError : public Error
    {
    public:
        PassphraseError(const std::string& message, bool missing) : Error(message), missing(missing) {}

        bool Missing() const { return missing; }

    private:
        bool missing;
    };

    struct EncryptResult
    {
        std::string message;
        std::string recipient;
        std::string keyId;
    };

    struct DecryptResult
    {
        std::string message;
        std::string keyId;
    };

    struct KeyInfo
    {
        bool secret = false;
        std::string userId;
        std::string keyId;
    };

    EncryptResult EncryptMessage(std::string_view message, std::string_view publicKey);
    DecryptResult DecryptMessage(std::string_view message, std::string_view privateKey, std::string_view passphrase);
    // the My PGP tab uses this to check what got pasted before saving it
    KeyInfo InspectKey(std::string_view armored);
}
