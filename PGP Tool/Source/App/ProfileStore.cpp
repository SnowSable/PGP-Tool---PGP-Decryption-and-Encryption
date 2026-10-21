#include "ProfileStore.h"

#include "Primitives.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dpapi.h>

#include <cstring>
#include <stdexcept>
#include <string_view>

namespace
{
    // lives at HKEY_CURRENT_USER\Software\PGPTool -> Profile. no files anywhere
    constexpr wchar_t RegistryKey[] = L"Software\\PGPTool";
    constexpr wchar_t RegistryValue[] = L"Profile";
    constexpr wchar_t BlobDescription[] = L"PGP Tool profile";
    // extra secret input to DPAPI, another app calling CryptUnprotectData on our blob would need this too
    constexpr char Entropy[] = "PGPTool.Profile.v1";
    // 'PGT' + version 1 at the start of the decrypted blob so we know it's ours and can change the format later
    constexpr uint8_t Magic[4] = { 'P', 'G', 'T', 1 };

    class LocalBlob
    {
    public:
        ~LocalBlob()
        {
            if (blob.pbData)
            {
                SecureZeroMemory(blob.pbData, blob.cbData);
                LocalFree(blob.pbData);
            }
        }

        DATA_BLOB blob = {};
    };

    DATA_BLOB EntropyBlob()
    {
        DATA_BLOB entropy;
        entropy.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(Entropy));
        entropy.cbData = static_cast<DWORD>(sizeof(Entropy) - 1);
        return entropy;
    }

    void WriteField(Pgp::Bytes& out, std::string_view field)
    {
        uint32_t size = static_cast<uint32_t>(field.size());
        for (int shift = 0; shift < 32; shift += 8)
            out.push_back(static_cast<uint8_t>(size >> shift));
        out.insert(out.end(), field.begin(), field.end());
    }

    std::string_view ReadField(const uint8_t* data, size_t size, size_t& position)
    {
        if (size - position < 4)
            throw std::runtime_error("The saved information is damaged");
        uint32_t length = 0;
        for (int i = 0; i < 4; ++i)
            length |= uint32_t(data[position + i]) << (8 * i);
        position += 4;
        if (size - position < length)
            throw std::runtime_error("The saved information is damaged");
        std::string_view field(reinterpret_cast<const char*>(data + position), length);
        position += length;
        return field;
    }

    std::wstring ErrorText(LSTATUS status)
    {
        wchar_t* message = nullptr;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, static_cast<DWORD>(status), 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
        std::wstring text = message ? message : L"";
        if (message)
            LocalFree(message);
        return text;
    }

    [[noreturn]] void Fail(const char* action, LSTATUS status)
    {
        std::wstring detail = ErrorText(status);
        std::string narrow;
        for (wchar_t c : detail)
            if (c != L'\r' && c != L'\n')
                narrow += c < 128 ? static_cast<char>(c) : '?';
        throw std::runtime_error(std::string(action) + (narrow.empty() ? "" : ": " + narrow));
    }
}

namespace ProfileStore
{
    // reads the registry blob, DPAPI decrypts it (only works for the same windows user), then splits out the 4 fields
    bool Load(Profile& profile)
    {
        DWORD size = 0;
        LSTATUS status = RegGetValueW(HKEY_CURRENT_USER, RegistryKey, RegistryValue, RRF_RT_REG_BINARY, nullptr, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND)
            return false;
        if (status != ERROR_SUCCESS)
            Fail("The saved information could not be read", status);

        Pgp::Bytes sealed(size);
        status = RegGetValueW(HKEY_CURRENT_USER, RegistryKey, RegistryValue, RRF_RT_REG_BINARY, nullptr, sealed.data(), &size);
        if (status != ERROR_SUCCESS)
            Fail("The saved information could not be read", status);
        sealed.resize(size);

        DATA_BLOB input = { static_cast<DWORD>(sealed.size()), sealed.data() };
        DATA_BLOB entropy = EntropyBlob();
        LocalBlob output;
        if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output.blob))
            throw std::runtime_error("The saved information could not be unlocked by this Windows account");

        const uint8_t* data = output.blob.pbData;
        size_t length = output.blob.cbData;
        if (length < sizeof(Magic) || std::memcmp(data, Magic, sizeof(Magic)) != 0)
            throw std::runtime_error("The saved information is damaged");

        size_t position = sizeof(Magic);
        std::string_view name = ReadField(data, length, position);
        std::string_view email = ReadField(data, length, position);
        std::string_view publicKey = ReadField(data, length, position);
        std::string_view privateKey = ReadField(data, length, position);

        profile.name.assign(name);
        profile.email.assign(email);
        profile.publicKey.assign(publicKey);
        profile.privateKey.Assign(privateKey);
        return true;
    }

    // yeah basically this packs name/email/public/private into one length-prefixed blob,
    // encrypts it with DPAPI tied to your windows login and dumps it in the registry
    void Save(const Profile& profile)
    {
        Pgp::Bytes plain(Magic, Magic + sizeof(Magic));
        plain.reserve(sizeof(Magic) + 16 + profile.name.size() + profile.email.size() + profile.publicKey.size() + profile.privateKey.Size());
        WriteField(plain, profile.name);
        WriteField(plain, profile.email);
        WriteField(plain, profile.publicKey);
        WriteField(plain, profile.privateKey.View());

        DATA_BLOB input = { static_cast<DWORD>(plain.size()), plain.data() };
        DATA_BLOB entropy = EntropyBlob();
        LocalBlob output;
        BOOL sealed = CryptProtectData(&input, BlobDescription, &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output.blob);
        Pgp::Wipe(plain);
        if (!sealed)
            Fail("The information could not be encrypted", static_cast<LSTATUS>(GetLastError()));

        HKEY key = nullptr;
        LSTATUS status = RegCreateKeyExW(HKEY_CURRENT_USER, RegistryKey, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr);
        if (status != ERROR_SUCCESS)
            Fail("The information could not be saved", status);
        status = RegSetValueExW(key, RegistryValue, 0, REG_BINARY, output.blob.pbData, output.blob.cbData);
        RegCloseKey(key);
        if (status != ERROR_SUCCESS)
            Fail("The information could not be saved", status);
    }

    // the Clear button lands here after the confirm popup
    void Erase()
    {
        LSTATUS status = RegDeleteKeyValueW(HKEY_CURRENT_USER, RegistryKey, RegistryValue);
        if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
            Fail("The saved information could not be cleared", status);
        RegDeleteKeyW(HKEY_CURRENT_USER, RegistryKey);
    }
}
