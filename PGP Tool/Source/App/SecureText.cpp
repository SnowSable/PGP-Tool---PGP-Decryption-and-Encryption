#include "SecureText.h"

#include "Primitives.h"

#include <algorithm>
#include <cstring>

namespace
{
    constexpr size_t InitialCapacity = 256;
}

SecureText::SecureText() : buffer(InitialCapacity, '\0')
{
}

SecureText::~SecureText()
{
    Pgp::WipeMemory(buffer.data(), buffer.size());
}

void SecureText::Assign(std::string_view text)
{
    Grow(text.size() + 1);
    Pgp::WipeMemory(buffer.data(), buffer.size());
    std::memcpy(buffer.data(), text.data(), text.size());
    length = text.size();
}

// copy into a bigger buffer, then scrub the old one before it gets freed
void SecureText::Grow(size_t capacity)
{
    if (capacity <= buffer.size())
        return;
    std::vector<char> larger(std::max(capacity, buffer.size() * 2), '\0');
    std::memcpy(larger.data(), buffer.data(), buffer.size());
    Pgp::WipeMemory(buffer.data(), buffer.size());
    buffer.swap(larger);
}

// imgui edits the buffer behind our back, this re-reads the length afterwards
void SecureText::Sync()
{
    length = strnlen(buffer.data(), buffer.size());
}

void SecureText::Clear()
{
    Pgp::WipeMemory(buffer.data(), buffer.size());
    length = 0;
}
