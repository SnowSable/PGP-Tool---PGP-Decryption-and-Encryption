#pragma once

#include "SecureText.h"

#include <string>

// everything the My PGP tab saves. private key is a SecureText so it gets wiped
struct Profile
{
    std::string name;
    std::string email;
    std::string publicKey;
    SecureText privateKey;
};

namespace ProfileStore
{
    bool Load(Profile& profile);
    void Save(const Profile& profile);
    void Erase();
}
