#include "Theme.h"

#include "imgui.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <string>

namespace Theme
{
    namespace
    {
        ImVec4 Gray(float value, float alpha = 1.0f)
        {
            return ImVec4(value, value, value, alpha);
        }

        std::string FontPath(const char* file)
        {
            char directory[MAX_PATH] = {};
            UINT length = GetWindowsDirectoryA(directory, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
                return {};
            std::string path = std::string(directory) + "\\Fonts\\" + file;
            return GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES ? std::string() : path;
        }

        ImFont* LoadFont(const char* file, float size)
        {
            std::string path = FontPath(file);
            if (path.empty())
                return nullptr;
            return ImGui::GetIO().Fonts->AddFontFromFileTTF(path.c_str(), size);
        }

        void MergeFont(const char* file, float size)
        {
            std::string path = FontPath(file);
            if (path.empty())
                return;
            ImFontConfig config;
            config.MergeMode = true;
            ImGui::GetIO().Fonts->AddFontFromFileTTF(path.c_str(), size, &config);
        }
    }

    // all the black and white styling. gets re-run if you drag the window onto a monitor with different scaling
    void Apply(float scale)
    {
        ImGuiStyle& style = ImGui::GetStyle();
        // reset first or ScaleAllSizes stacks on top of itself every time the dpi changes
        style = ImGuiStyle();
        ImGui::StyleColorsDark(&style);

        style.WindowPadding = ImVec2(24.0f, 20.0f);
        style.FramePadding = ImVec2(10.0f, 8.0f);
        style.ItemSpacing = ImVec2(12.0f, 10.0f);
        style.ItemInnerSpacing = ImVec2(8.0f, 6.0f);
        style.ScrollbarSize = 10.0f;
        style.WindowRounding = 0.0f;
        style.ChildRounding = 4.0f;
        style.FrameRounding = 4.0f;
        style.PopupRounding = 6.0f;
        style.ScrollbarRounding = 4.0f;
        style.GrabRounding = 4.0f;
        style.TabRounding = 4.0f;
        style.WindowBorderSize = 0.0f;
        style.FrameBorderSize = 1.0f;
        style.PopupBorderSize = 1.0f;
        style.TabBorderSize = 0.0f;
        style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
        style.FontSizeBase = TextSize;

        ImVec4* colors = style.Colors;
        colors[ImGuiCol_Text] = Gray(1.0f);
        colors[ImGuiCol_TextDisabled] = Gray(0.52f);
        colors[ImGuiCol_WindowBg] = Gray(0.0f);
        colors[ImGuiCol_ChildBg] = Gray(0.0f);
        colors[ImGuiCol_PopupBg] = Gray(0.03f);
        colors[ImGuiCol_Border] = Gray(0.22f);
        colors[ImGuiCol_BorderShadow] = Gray(0.0f, 0.0f);
        colors[ImGuiCol_FrameBg] = Gray(0.035f);
        colors[ImGuiCol_FrameBgHovered] = Gray(0.06f);
        colors[ImGuiCol_FrameBgActive] = Gray(0.08f);
        colors[ImGuiCol_TitleBg] = Gray(0.0f);
        colors[ImGuiCol_TitleBgActive] = Gray(0.0f);
        colors[ImGuiCol_TitleBgCollapsed] = Gray(0.0f);
        colors[ImGuiCol_MenuBarBg] = Gray(0.0f);
        colors[ImGuiCol_ScrollbarBg] = Gray(0.0f, 0.0f);
        colors[ImGuiCol_ScrollbarGrab] = Gray(0.25f);
        colors[ImGuiCol_ScrollbarGrabHovered] = Gray(0.4f);
        colors[ImGuiCol_ScrollbarGrabActive] = Gray(0.55f);
        colors[ImGuiCol_CheckMark] = Gray(1.0f);
        colors[ImGuiCol_SliderGrab] = Gray(0.7f);
        colors[ImGuiCol_SliderGrabActive] = Gray(1.0f);
        colors[ImGuiCol_Button] = Gray(0.06f);
        colors[ImGuiCol_ButtonHovered] = Gray(0.16f);
        colors[ImGuiCol_ButtonActive] = Gray(0.26f);
        colors[ImGuiCol_Header] = Gray(0.12f);
        colors[ImGuiCol_HeaderHovered] = Gray(0.18f);
        colors[ImGuiCol_HeaderActive] = Gray(0.24f);
        colors[ImGuiCol_Separator] = Gray(0.22f);
        colors[ImGuiCol_SeparatorHovered] = Gray(0.5f);
        colors[ImGuiCol_SeparatorActive] = Gray(1.0f);
        colors[ImGuiCol_ResizeGrip] = Gray(0.0f, 0.0f);
        colors[ImGuiCol_ResizeGripHovered] = Gray(0.0f, 0.0f);
        colors[ImGuiCol_ResizeGripActive] = Gray(0.0f, 0.0f);
        colors[ImGuiCol_InputTextCursor] = Gray(1.0f);
        colors[ImGuiCol_Tab] = Gray(0.0f);
        colors[ImGuiCol_TabHovered] = Gray(0.12f);
        colors[ImGuiCol_TabSelected] = Gray(0.09f);
        colors[ImGuiCol_TabSelectedOverline] = Gray(1.0f);
        colors[ImGuiCol_TabDimmed] = Gray(0.0f);
        colors[ImGuiCol_TabDimmedSelected] = Gray(0.09f);
        colors[ImGuiCol_TabDimmedSelectedOverline] = Gray(0.6f);
        colors[ImGuiCol_TextSelectedBg] = Gray(1.0f, 0.22f);
        colors[ImGuiCol_DragDropTarget] = Gray(1.0f);
        colors[ImGuiCol_NavCursor] = Gray(1.0f);
        colors[ImGuiCol_NavWindowingHighlight] = Gray(1.0f, 0.7f);
        colors[ImGuiCol_NavWindowingDimBg] = Gray(0.0f, 0.6f);
        colors[ImGuiCol_ModalWindowDimBg] = Gray(0.0f, 0.72f);

        style.ScaleAllSizes(scale);
        style.FontScaleDpi = scale;
    }

    // segoe ui for normal text, consolas for keys/armor. merges in the symbol + chinese fonts
    // so stuff like the tick and non-latin text doesn't turn into ?
    Fonts LoadFonts()
    {
        ImGuiIO& io = ImGui::GetIO();
        Fonts fonts;

        fonts.text = LoadFont("segoeui.ttf", TextSize);
        if (fonts.text)
        {
            MergeFont("seguisym.ttf", TextSize);
            MergeFont("msyh.ttc", TextSize);
        }
        else
        {
            fonts.text = io.Fonts->AddFontDefault();
        }

        fonts.mono = LoadFont("consola.ttf", MonoSize);
        if (fonts.mono)
            MergeFont("segoeui.ttf", MonoSize);
        else
            fonts.mono = fonts.text;

        io.FontDefault = fonts.text;
        return fonts;
    }

    // white button black text, used for the main action on each tab
    void PushPrimaryButton()
    {
        ImGui::PushStyleColor(ImGuiCol_Button, Gray(1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Gray(0.86f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, Gray(0.72f));
        ImGui::PushStyleColor(ImGuiCol_Text, Gray(0.0f));
        ImGui::PushStyleColor(ImGuiCol_Border, Gray(1.0f));
    }

    void PushSecondaryButton()
    {
        ImGui::PushStyleColor(ImGuiCol_Button, Gray(0.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, Gray(0.12f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, Gray(0.22f));
        ImGui::PushStyleColor(ImGuiCol_Text, Gray(1.0f));
        ImGui::PushStyleColor(ImGuiCol_Border, Gray(0.6f));
    }

    void PopButton()
    {
        ImGui::PopStyleColor(5);
    }
}
