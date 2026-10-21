#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

// a text buffer that zeroes itself whenever it grows, gets cleared or dies.
// std::string can't do that, it reallocates and leaves the old copy lying in freed memory.
// imgui writes straight into it through the resize callback in Application.cpp line 103
class SecureText
{
public:
    SecureText();
    ~SecureText();

    SecureText(const SecureText&) = delete;
    SecureText& operator=(const SecureText&) = delete;

    char* Data() { return buffer.data(); }
    size_t Capacity() const { return buffer.size(); }
    size_t Size() const { return length; }
    bool Empty() const { return length == 0; }
    std::string_view View() const { return std::string_view(buffer.data(), length); }

    void Assign(std::string_view text);
    void Grow(size_t capacity);
    void Sync();
    void Clear();

private:
    std::vector<char> buffer;
    size_t length = 0;
};
