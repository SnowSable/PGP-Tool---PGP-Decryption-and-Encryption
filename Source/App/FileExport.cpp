#include "FileExport.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>

#include <stdexcept>

namespace
{
    std::wstring Widen(const std::string& text)
    {
        if (text.empty())
            return {};
        int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        std::wstring wide(static_cast<size_t>(size), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), size);
        return wide;
    }

    std::wstring DownloadsFolder()
    {
        PWSTR path = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &path)))
        {
            CoTaskMemFree(path);
            throw std::runtime_error("Couldn't find your Downloads folder");
        }
        std::wstring folder = path;
        CoTaskMemFree(path);
        return folder;
    }

    // "Alice Public Key.txt" -> "Alice Public Key (2).txt" -> "(3)"... until we find a name that isn't taken
    std::wstring UniquePath(const std::wstring& folder, const std::wstring& name)
    {
        size_t dot = name.rfind(L'.');
        std::wstring stem = dot == std::wstring::npos ? name : name.substr(0, dot);
        std::wstring extension = dot == std::wstring::npos ? L"" : name.substr(dot);
        std::wstring path = folder + L"\\" + name;
        for (int copy = 2; GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; ++copy)
            path = folder + L"\\" + stem + L" (" + std::to_wstring(copy) + L")" + extension;
        return path;
    }

    void WriteText(const std::wstring& path, const std::string& contents)
    {
        std::string windowsText;
        windowsText.reserve(contents.size() + contents.size() / 32);
        for (char c : contents)
        {
            if (c == '\n')
                windowsText += '\r';
            windowsText += c;
        }

        HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            throw std::runtime_error("Couldn't create a file in your Downloads folder");
        DWORD written = 0;
        BOOL ok = WriteFile(file, windowsText.data(), static_cast<DWORD>(windowsText.size()), &written, nullptr);
        CloseHandle(file);
        SecureZeroMemory(windowsText.data(), windowsText.size());
        if (!ok || written != windowsText.size())
            throw std::runtime_error("Couldn't write a file in your Downloads folder");
    }
}

namespace FileExport
{
    std::vector<std::wstring> SaveToDownloads(const std::vector<File>& files)
    {
        std::wstring folder = DownloadsFolder();
        std::vector<std::wstring> paths;
        for (const File& file : files)
        {
            std::wstring path = UniquePath(folder, Widen(file.name));
            WriteText(path, file.contents);
            paths.push_back(path);
        }
        return paths;
    }

    void ShowInExplorer(const std::wstring& path)
    {
        std::wstring arguments = L"/select,\"" + path + L"\"";
        ShellExecuteW(nullptr, L"open", L"explorer.exe", arguments.c_str(), nullptr, SW_SHOWNORMAL);
    }

    // strips the characters windows won't allow in file names, so "Bob <bob@x.com>" can't break anything
    std::string SafeFileName(const std::string& text)
    {
        std::string out;
        for (char c : text)
        {
            if (static_cast<unsigned char>(c) < 32 || std::string("<>:\"/\\|?*").find(c) != std::string::npos)
                continue;
            out += c;
        }
        size_t start = out.find_first_not_of(" .");
        size_t end = out.find_last_not_of(" .");
        return start == std::string::npos ? std::string() : out.substr(start, end - start + 1);
    }
}
