#pragma once

struct ImFont;

namespace Theme
{
    struct Fonts
    {
        ImFont* text = nullptr;
        ImFont* mono = nullptr;
    };

    constexpr float TextSize = 16.0f;
    constexpr float MonoSize = 13.0f;
    constexpr float LabelSize = 12.5f;

    void Apply(float scale);
    Fonts LoadFonts();

    void PushPrimaryButton();
    void PushSecondaryButton();
    void PopButton();
}
