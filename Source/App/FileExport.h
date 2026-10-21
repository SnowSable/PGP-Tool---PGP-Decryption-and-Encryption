#pragma once

#include <string>
#include <vector>

namespace FileExport
{
    struct File
    {
        std::string name;
        std::string contents;
    };

    // writes each file into the user's Downloads folder (never overwrites, adds " (2)" etc instead)
    // and returns the full paths it actually used
    std::vector<std::wstring> SaveToDownloads(const std::vector<File>& files);
    void ShowInExplorer(const std::wstring& path);
    std::string SafeFileName(const std::string& text);
}
