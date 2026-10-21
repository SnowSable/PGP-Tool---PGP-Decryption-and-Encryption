#pragma once

#include <cstdint>

namespace Pgp
{
    void X25519(uint8_t output[32], const uint8_t scalar[32], const uint8_t point[32]);
    void X25519Base(uint8_t output[32], const uint8_t scalar[32]);
}
