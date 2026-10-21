#pragma once

#include "Primitives.h"

#include <string_view>

namespace Pgp
{
    std::string Armor(const Bytes& data, const std::string& type);
    Bytes Dearmor(std::string_view text, std::string& type);
}
