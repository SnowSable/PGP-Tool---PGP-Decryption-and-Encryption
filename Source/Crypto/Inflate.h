#pragma once

#include "Primitives.h"

namespace Pgp
{
    Bytes Inflate(const uint8_t* data, size_t size);
    Bytes InflateZlib(const uint8_t* data, size_t size);
}
