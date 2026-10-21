#include "Application.h"

#include "OpenPgp.h"

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_stdlib.h"

#include <algorithm>

namespace
{
    enum Action
    {
        ActionNone,
        ActionPrimary,
        ActionSecondary
    };

    constexpr const char* PassphrasePopup = "Passphrase Required";
    constexpr const char* ClearPopup = "Clear Saved Information";
    constexpr double CopiedDuration = 1.6;

    // all the layout magic numbers live here so you can tweak the look without hunting through the file
    constexpr float TopSpacing = 2.0f;
    constexpr float LabelRowScale = 0.78f;
    constexpr float LabelGap = 6.0f;
    constexpr float ActionButtonScale = 1.2f;
    constexpr float TabPaddingScale = 2.2f;
    constexpr float MinimumBoxHeight = 90.0f;
    constexpr float PrimaryButtonWidth = 170.0f;
    constexpr float SecondaryButtonWidth = 110.0f;
    constexpr float PopupWidth = 440.0f;
    constexpr float PopupGap = 4.0f;
    constexpr float HeaderButtonPadding = 3.0f;
    constexpr float ActionButtonPadding = 4.0f;
    constexpr float StatusGapScale = 2.0f;

    std::string FormatKeyId(const std::string& hex)
    {
        std::string out;
        for (size_t i = 0; i < hex.size(); ++i)
        {
            if (i && i % 4 == 0)
                out += ' ';
            out += hex[i];
        }
        return out;
    }

    bool IsBlank(std::string_view text)
    {
        return text.find_first_not_of(" \t\r\n") == std::string_view::npos;
    }

    std::string_view Trim(std::string_view text)
    {
        size_t start = text.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos)
            return {};
        size_t end = text.find_last_not_of(" \t\r\n");
        return text.substr(start, end - start + 1);
    }

    void SplitUserId(std::string_view userId, std::string& name, std::string& email)
    {
        size_t open = userId.rfind('<');
        size_t close = userId.rfind('>');
        if (open != std::string_view::npos && close != std::string_view::npos && close > open)
        {
            email = Trim(userId.substr(open + 1, close - open - 1));
            name = Trim(userId.substr(0, open));
        }
        else
        {
            name = Trim(userId);
        }
    }

    // imgui uses \n but some windows apps want \r\n when you paste, so convert before copying
    void CopyToClipboard(const std::string& text)
    {
        std::string windowsText;
        windowsText.reserve(text.size() + text.size() / 32);
        for (char c : text)
        {
            if (c == '\n')
                windowsText += '\r';
            windowsText += c;
        }
        ImGui::SetClipboardText(windowsText.c_str());
        Pgp::Wipe(windowsText);
    }

    // imgui calls this when the text outgrows the buffer, we grow the SecureText (which wipes the old one)
    int ResizeSecureText(ImGuiInputTextCallbackData* data)
    {
        if (data->EventFlag == ImGuiInputTextFlags_CallbackResize)
        {
            auto text = static_cast<SecureText*>(data->UserData);
            text->Grow(static_cast<size_t>(data->BufSize));
            data->Buf = text->Data();
        }
        return 0;
    }

    float Scale()
    {
        return ImGui::GetStyle().FontScaleDpi;
    }

    float LabelRowHeight()
    {
        return ImGui::GetFrameHeight() * LabelRowScale;
    }

    float LabelBlockHeight()
    {
        return LabelRowHeight() + LabelGap * Scale();
    }

    float ActionButtonHeight()
    {
        return ImGui::GetFrameHeight() * ActionButtonScale;
    }
}

// loads whatever got saved in My PGP last time, if anything
Application::Application(const Theme::Fonts& fonts) : fonts(fonts)
{
    try
    {
        hasSavedProfile = ProfileStore::Load(profile);
        hasSavedPrivateKey = hasSavedProfile && !profile.privateKey.Empty();
    }
    catch (const std::exception& error)
    {
        profileStatus = { error.what(), StatusKind::Failure };
    }
}

Application::~Application()
{
    ResetEncrypt();
    ResetDecrypt();
    Pgp::Wipe(profile.publicKey);
    profile.privateKey.Clear();
}

// one full-window imgui window with the 3 tabs. runs every frame from Main.cpp line 259
void Application::Render()
{
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("##Main", nullptr, flags);

    const ImGuiStyle& style = ImGui::GetStyle();
    if (ImGui::BeginTabBar("##Tabs"))
    {
        ImVec2 tabPadding(style.FramePadding.x * TabPaddingScale, style.FramePadding.y);
        struct Tab
        {
            const char* name;
            void (Application::*render)();
        };
        const Tab tabs[] = {
            { "Encrypt", &Application::RenderEncryptTab },
            { "Decrypt", &Application::RenderDecryptTab },
            { "My PGP", &Application::RenderProfileTab },
        };

        for (const Tab& tab : tabs)
        {
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, tabPadding);
            bool open = ImGui::BeginTabItem(tab.name);
            ImGui::PopStyleVar();
            if (open)
            {
                (this->*tab.render)();
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }

    RenderPassphrasePopup();
    RenderClearPopup();
    ImGui::End();
}

void Application::RenderEncryptTab()
{
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::Dummy(ImVec2(0.0f, TopSpacing * Scale()));

    ImVec2 available = ImGui::GetContentRegionAvail();
    float columnWidth = (available.x - style.ItemSpacing.x) * 0.5f;
    float fixed = LabelBlockHeight() * 2.0f + ActionButtonHeight() + style.ItemSpacing.y * 6.0f;
    float inputHeight = std::max((available.y - fixed) * 0.5f, MinimumBoxHeight * Scale());

    ImGui::BeginGroup();
    Label("MESSAGE");
    TextBox("##Message", plainMessage, columnWidth, inputHeight, false, false, "Type the message you want to encrypt");
    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();
    Label("RECIPIENT PUBLIC KEY");
    TextBox("##PublicKey", publicKey, columnWidth, inputHeight, false, true, "Paste the recipient's public key\n-----BEGIN PGP PUBLIC KEY BLOCK-----");
    ImGui::EndGroup();

    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));
    int action = ActionButtons("Encrypt Message", "Reset", encryptStatus);
    if (action == ActionPrimary)
        Encrypt();
    else if (action == ActionSecondary)
        ResetEncrypt();
    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));

    float outputHeight = std::max(ImGui::GetContentRegionAvail().y - LabelBlockHeight(), MinimumBoxHeight * Scale());
    OutputPanel("##EncryptedOutput", "ENCRYPTED PGP MESSAGE", encryptedOutput, encryptCopiedAt, outputHeight, true, "The encrypted message will appear here");
}

void Application::RenderDecryptTab()
{
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::Dummy(ImVec2(0.0f, TopSpacing * Scale()));

    ImVec2 available = ImGui::GetContentRegionAvail();
    float columnWidth = (available.x - style.ItemSpacing.x) * 0.5f;
    float fixed = LabelBlockHeight() * 2.0f + ActionButtonHeight() + style.ItemSpacing.y * 6.0f;
    float inputHeight = std::max((available.y - fixed) * 0.5f, MinimumBoxHeight * Scale());

    ImGui::BeginGroup();
    Label("ENCRYPTED PGP MESSAGE");
    TextBox("##EncryptedMessage", encryptedMessage, columnWidth, inputHeight, false, true, "Paste the encrypted message\n-----BEGIN PGP MESSAGE-----");
    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();
    const char* useSaved = hasSavedPrivateKey ? "Use Saved Key" : nullptr;
    if (Header("PRIVATE PGP KEY", columnWidth, useSaved, useSaved, true))
        UseSavedKey();
    TextBox("##PrivateKey", privateKey, columnWidth, inputHeight, true, "Paste your private key\n-----BEGIN PGP PRIVATE KEY BLOCK-----");
    ImGui::EndGroup();

    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));
    int action = ActionButtons("Decrypt Message", "Reset", decryptStatus);
    if (action == ActionPrimary)
    {
        passphrase.Clear();
        Decrypt();
    }
    else if (action == ActionSecondary)
    {
        ResetDecrypt();
    }
    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));

    float outputHeight = std::max(ImGui::GetContentRegionAvail().y - LabelBlockHeight(), MinimumBoxHeight * Scale());
    OutputPanel("##DecryptedOutput", "DECRYPTED MESSAGE", decryptedOutput, decryptCopiedAt, outputHeight, false, "The decrypted message will appear here");
}

// the My PGP tab. name/email up top, keys side by side, save/clear at the bottom
void Application::RenderProfileTab()
{
    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::Dummy(ImVec2(0.0f, TopSpacing * Scale()));

    float columnWidth = (ImGui::GetContentRegionAvail().x - style.ItemSpacing.x) * 0.5f;

    ImGui::BeginGroup();
    Label("NAME");
    ImGui::SetNextItemWidth(columnWidth);
    ImGui::InputTextWithHint("##Name", "Your name", &profile.name);
    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();
    Label("EMAIL");
    ImGui::SetNextItemWidth(columnWidth);
    ImGui::InputTextWithHint("##Email", "you@example.com", &profile.email);
    ImGui::EndGroup();

    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));
    float reserved = LabelBlockHeight() + ActionButtonHeight() + style.ItemSpacing.y * 3.0f;
    float keyHeight = std::max(ImGui::GetContentRegionAvail().y - reserved, MinimumBoxHeight * Scale());

    ImGui::BeginGroup();
    bool copied = ImGui::GetTime() - profileCopiedAt < CopiedDuration;
    if (Header("PUBLIC KEY", columnWidth, copied ? "Copied###Copy" : "Copy###Copy", "Copied", !IsBlank(profile.publicKey)))
    {
        CopyToClipboard(profile.publicKey);
        profileCopiedAt = ImGui::GetTime();
    }
    TextBox("##ProfilePublicKey", profile.publicKey, columnWidth, keyHeight, false, true, "Paste your public key\n-----BEGIN PGP PUBLIC KEY BLOCK-----");
    ImGui::EndGroup();
    ImGui::SameLine();
    ImGui::BeginGroup();
    Label("PRIVATE KEY");
    TextBox("##ProfilePrivateKey", profile.privateKey, columnWidth, keyHeight, true, "Paste your private key\n-----BEGIN PGP PRIVATE KEY BLOCK-----");
    ImGui::EndGroup();

    ImGui::Dummy(ImVec2(0.0f, style.ItemSpacing.y * 0.5f));
    int action = ActionButtons("Save", "Clear", profileStatus);
    if (action == ActionPrimary)
        SaveProfile();
    else if (action == ActionSecondary)
        ClearProfile();
}

// shared setup for both popups. 'requested' is our own flag, imgui wants popups opened
// from the same id stack they're drawn in, so the opening happens here and not in the tabs
bool Application::BeginModal(const char* name, bool requested)
{
    if (requested && !ImGui::IsPopupOpen(name))
        ImGui::OpenPopup(name);

    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(PopupWidth * Scale(), 0.0f));
    if (!ImGui::BeginPopupModal(name, nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings))
        return false;

    if (!requested)
    {
        ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
        return false;
    }
    return true;
}

void Application::RenderPassphrasePopup()
{
    if (!BeginModal(PassphrasePopup, passphraseRequested))
        return;

    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::PushStyleColor(ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled]);
    ImGui::TextWrapped("This private key is protected. Enter its passphrase to decrypt the message.");
    ImGui::PopStyleColor();
    ImGui::Dummy(ImVec2(0.0f, PopupGap * 0.5f * Scale()));

    if (ImGui::IsWindowAppearing() || focusPassphrase)
    {
        ImGui::SetKeyboardFocusHere();
        focusPassphrase = false;
    }
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackResize;
    bool submitted = ImGui::InputText("##Passphrase", passphrase.Data(), passphrase.Capacity(), flags, ResizeSecureText, &passphrase);
    passphrase.Sync();

    if (!passphraseError.empty())
        ImGui::TextWrapped("\xE2\x9C\x95  %s", passphraseError.c_str());

    ImGui::Dummy(ImVec2(0.0f, PopupGap * Scale()));
    float buttonWidth = (ImGui::GetContentRegionAvail().x - style.ItemSpacing.x) * 0.5f;
    float buttonHeight = ImGui::GetFrameHeight() * 1.1f;

    Theme::PushPrimaryButton();
    bool unlock = ImGui::Button("Unlock", ImVec2(buttonWidth, buttonHeight));
    Theme::PopButton();
    ImGui::SameLine();
    Theme::PushSecondaryButton();
    bool cancel = ImGui::Button("Cancel", ImVec2(buttonWidth, buttonHeight));
    Theme::PopButton();

    if (submitted || unlock)
    {
        Decrypt();
        if (!passphraseRequested)
            ImGui::CloseCurrentPopup();
    }
    else if (cancel || ImGui::IsKeyPressed(ImGuiKey_Escape))
    {
        passphraseRequested = false;
        passphrase.Clear();
        passphraseError.clear();
        decryptStatus = { "Decryption cancelled", StatusKind::None };
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

void Application::RenderClearPopup()
{
    if (!BeginModal(ClearPopup, clearRequested))
        return;

    const ImGuiStyle& style = ImGui::GetStyle();
    ImGui::PushStyleColor(ImGuiCol_Text, style.Colors[ImGuiCol_TextDisabled]);
    ImGui::TextWrapped("This permanently deletes your saved name, email and keys from this computer.");
    ImGui::PopStyleColor();
    ImGui::Dummy(ImVec2(0.0f, PopupGap * Scale()));

    float buttonWidth = (ImGui::GetContentRegionAvail().x - style.ItemSpacing.x) * 0.5f;
    float buttonHeight = ImGui::GetFrameHeight() * 1.1f;

    Theme::PushPrimaryButton();
    bool confirm = ImGui::Button("Clear", ImVec2(buttonWidth, buttonHeight));
    Theme::PopButton();
    ImGui::SameLine();
    Theme::PushSecondaryButton();
    bool cancel = ImGui::Button("Cancel", ImVec2(buttonWidth, buttonHeight));
    Theme::PopButton();

    if (confirm)
    {
        try
        {
            ProfileStore::Erase();
            Pgp::Wipe(profile.name);
            Pgp::Wipe(profile.email);
            Pgp::Wipe(profile.publicKey);
            profile.privateKey.Clear();
            hasSavedProfile = false;
            hasSavedPrivateKey = false;
            profileStatus = { "Saved information cleared", StatusKind::Success };
        }
        catch (const std::exception& error)
        {
            profileStatus = { error.what(), StatusKind::Failure };
        }
        clearRequested = false;
        ImGui::CloseCurrentPopup();
    }
    else if (cancel || ImGui::IsKeyPressed(ImGuiKey_Escape))
    {
        clearRequested = false;
        ImGui::CloseCurrentPopup();
    }

    ImGui::EndPopup();
}

void Application::Encrypt()
{
    try
    {
        Pgp::EncryptResult result = Pgp::EncryptMessage(plainMessage, publicKey);
        Pgp::Wipe(encryptedOutput);
        encryptedOutput = std::move(result.message);
        std::string text = "Encrypted";
        if (!result.recipient.empty())
            text += " for " + result.recipient;
        text += "  \xC2\xB7  key " + FormatKeyId(result.keyId);
        encryptStatus = { text, StatusKind::Success };
    }
    catch (const std::exception& error)
    {
        Pgp::Wipe(encryptedOutput);
        encryptStatus = { error.what(), StatusKind::Failure };
    }
}

// first go is with an empty passphrase. if the key needs one, PassphraseError flips passphraseRequested
// and the popup shows up, then Unlock in the popup calls back in here with whatever got typed
void Application::Decrypt()
{
    try
    {
        Pgp::DecryptResult result = Pgp::DecryptMessage(encryptedMessage, privateKey.View(), passphrase.View());
        Pgp::Wipe(decryptedOutput);
        decryptedOutput = std::move(result.message);
        Pgp::Wipe(result.message);
        decryptStatus = { "Decrypted with key " + FormatKeyId(result.keyId), StatusKind::Success };
        passphraseRequested = false;
        passphraseError.clear();
    }
    catch (const Pgp::PassphraseError& error)
    {
        if (!passphraseRequested)
        {
            passphraseRequested = true;
            passphraseError.clear();
        }
        else
        {
            passphraseError = error.Missing() ? "Enter the passphrase for this key" : error.what();
            focusPassphrase = true;
        }
    }
    catch (const std::exception& error)
    {
        Pgp::Wipe(decryptedOutput);
        decryptStatus = { error.what(), StatusKind::Failure };
        passphraseRequested = false;
        passphraseError.clear();
    }
    passphrase.Clear();
}

// the Use Saved Key button on the decrypt tab. reads fresh from the store instead of the My PGP form
// so half-finished edits over there don't sneak in
void Application::UseSavedKey()
{
    try
    {
        Profile saved;
        if (!ProfileStore::Load(saved) || saved.privateKey.Empty())
        {
            hasSavedPrivateKey = false;
            decryptStatus = { "No private key is saved in My PGP", StatusKind::Failure };
            return;
        }
        privateKey.Assign(saved.privateKey.View());
        decryptStatus = { "Loaded your saved private key", StatusKind::None };
    }
    catch (const std::exception& error)
    {
        decryptStatus = { error.what(), StatusKind::Failure };
    }
}

// makes sure the keys make sense before saving: right type in each box, same key pair, then fills
// name/email from the key if you left them blank. the actual saving is ProfileStore.cpp line 135
void Application::SaveProfile()
{
    bool hasPublic = !IsBlank(profile.publicKey);
    bool hasPrivate = !IsBlank(profile.privateKey.View());
    if (!hasPublic && !hasPrivate && IsBlank(profile.name) && IsBlank(profile.email))
    {
        profileStatus = { "Nothing to save, fill in at least one field", StatusKind::Failure };
        return;
    }

    Pgp::KeyInfo publicInfo;
    Pgp::KeyInfo privateInfo;
    try
    {
        if (hasPublic)
        {
            publicInfo = Pgp::InspectKey(profile.publicKey);
            // the string check catches a private key pasted AFTER a public one, InspectKey only reads the first block
            if (publicInfo.secret || profile.publicKey.find("PRIVATE KEY BLOCK") != std::string::npos)
                throw Pgp::Error("A private key was pasted into the Public Key box");
        }
    }
    catch (const std::exception& error)
    {
        profileStatus = { std::string("Public key: ") + error.what(), StatusKind::Failure };
        return;
    }

    try
    {
        if (hasPrivate)
        {
            privateInfo = Pgp::InspectKey(profile.privateKey.View());
            if (!privateInfo.secret)
                throw Pgp::Error("A public key was pasted into the Private Key box");
        }
    }
    catch (const std::exception& error)
    {
        profileStatus = { std::string("Private key: ") + error.what(), StatusKind::Failure };
        return;
    }

    if (hasPublic && hasPrivate && publicInfo.keyId != privateInfo.keyId)
    {
        profileStatus = { "The public and private keys belong to different key pairs", StatusKind::Failure };
        return;
    }

    const Pgp::KeyInfo& info = hasPrivate ? privateInfo : publicInfo;
    if (!info.userId.empty() && (IsBlank(profile.name) || IsBlank(profile.email)))
    {
        std::string name;
        std::string email;
        SplitUserId(info.userId, name, email);
        if (IsBlank(profile.name))
            profile.name = name;
        if (IsBlank(profile.email))
            profile.email = email;
    }

    try
    {
        ProfileStore::Save(profile);
        hasSavedProfile = true;
        hasSavedPrivateKey = hasPrivate;
        std::string text = "Saved and encrypted to your Windows account";
        if (!info.keyId.empty())
            text += "  \xC2\xB7  key " + FormatKeyId(info.keyId);
        profileStatus = { text, StatusKind::Success };
    }
    catch (const std::exception& error)
    {
        profileStatus = { error.what(), StatusKind::Failure };
    }
}

void Application::ClearProfile()
{
    if (hasSavedProfile)
    {
        clearRequested = true;
        return;
    }
    Pgp::Wipe(profile.name);
    Pgp::Wipe(profile.email);
    Pgp::Wipe(profile.publicKey);
    profile.privateKey.Clear();
    profileStatus = {};
}

void Application::ResetEncrypt()
{
    Pgp::Wipe(plainMessage);
    Pgp::Wipe(publicKey);
    Pgp::Wipe(encryptedOutput);
    encryptStatus = {};
    encryptCopiedAt = -10.0;
}

void Application::ResetDecrypt()
{
    Pgp::Wipe(encryptedMessage);
    privateKey.Clear();
    Pgp::Wipe(decryptedOutput);
    passphrase.Clear();
    passphraseError.clear();
    passphraseRequested = false;
    decryptStatus = {};
    decryptCopiedAt = -10.0;
}

void Application::Label(const char* text)
{
    float rowHeight = LabelRowHeight();
    ImVec2 position = ImGui::GetCursorScreenPos();
    ImGui::PushFont(fonts.text, Theme::LabelSize);
    float textHeight = ImGui::GetTextLineHeight();
    ImGui::GetWindowDrawList()->AddText(ImVec2(position.x + 1.0f, position.y + (rowHeight - textHeight) * 0.5f), ImGui::GetColorU32(ImGuiCol_TextDisabled), text);
    ImGui::PopFont();
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(ImGui::GetStyle().ItemSpacing.x, LabelGap * Scale()));
    ImGui::Dummy(ImVec2(1.0f, rowHeight));
    ImGui::PopStyleVar();
}

// the little label above each box, with an optional small button on the right (Copy, Use Saved Key)
bool Application::Header(const char* label, float width, const char* button, const char* widestButton, bool enabled)
{
    ImVec2 rowStart = ImGui::GetCursorScreenPos();
    Label(label);
    if (!button)
        return false;

    const ImGuiStyle& style = ImGui::GetStyle();
    ImVec2 afterLabel = ImGui::GetCursorScreenPos();
    float rowHeight = LabelRowHeight();

    ImGui::PushID(label);
    ImGui::PushFont(fonts.text, Theme::LabelSize);
    float buttonWidth = ImGui::CalcTextSize(widestButton ? widestButton : button, nullptr, true).x + style.FramePadding.x * HeaderButtonPadding;
    ImGui::SetCursorScreenPos(ImVec2(rowStart.x + width - buttonWidth, rowStart.y));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(style.FramePadding.x, 0.0f));
    ImGui::BeginDisabled(!enabled);
    Theme::PushSecondaryButton();
    bool clicked = ImGui::Button(button, ImVec2(buttonWidth, rowHeight));
    Theme::PopButton();
    ImGui::EndDisabled();
    ImGui::PopStyleVar();
    ImGui::PopFont();
    ImGui::PopID();

    ImGui::SetCursorScreenPos(afterLabel);
    return clicked;
}

void Application::TextBox(const char* id, std::string& text, float width, float height, bool readOnly, bool mono, const char* placeholder)
{
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_WordWrap;
    if (readOnly)
        flags |= ImGuiInputTextFlags_ReadOnly;

    if (mono)
        ImGui::PushFont(fonts.mono, Theme::MonoSize);
    ImGui::InputTextMultiline(id, &text, ImVec2(width, height), flags);
    if (mono)
        ImGui::PopFont();
    Placeholder(text.empty(), width, placeholder);
}

void Application::TextBox(const char* id, SecureText& text, float width, float height, bool mono, const char* placeholder)
{
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_WordWrap | ImGuiInputTextFlags_CallbackResize;

    if (mono)
        ImGui::PushFont(fonts.mono, Theme::MonoSize);
    ImGui::InputTextMultiline(id, text.Data(), text.Capacity(), ImVec2(width, height), flags, ResizeSecureText, &text);
    text.Sync();
    if (mono)
        ImGui::PopFont();
    Placeholder(text.Empty(), width, placeholder);
}

// imgui multiline boxes don't do placeholder text so we just draw grey text on top when it's empty
void Application::Placeholder(bool empty, float width, const char* placeholder)
{
    if (!empty || !placeholder || ImGui::IsItemActive())
        return;
    const ImGuiStyle& style = ImGui::GetStyle();
    ImVec2 position = ImGui::GetItemRectMin();
    position.x += style.FramePadding.x;
    position.y += style.FramePadding.y;
    ImGui::GetWindowDrawList()->AddText(ImGui::GetFont(), ImGui::GetFontSize(), position, ImGui::GetColorU32(ImGuiCol_TextDisabled, 0.75f), placeholder, nullptr, width - style.FramePadding.x * 2.0f);
}

void Application::OutputPanel(const char* id, const char* label, std::string& text, double& copiedAt, float height, bool mono, const char* placeholder)
{
    float width = ImGui::GetContentRegionAvail().x;
    bool copied = ImGui::GetTime() - copiedAt < CopiedDuration;
    if (Header(label, width, copied ? "Copied###Copy" : "Copy###Copy", "Copied", !text.empty()))
    {
        CopyToClipboard(text);
        copiedAt = ImGui::GetTime();
    }
    TextBox(id, text, width, height, true, mono, placeholder);
}

int Application::ActionButtons(const char* primary, const char* secondary, const Status& status)
{
    const ImGuiStyle& style = ImGui::GetStyle();
    float height = ActionButtonHeight();
    float primaryWidth = std::max(ImGui::CalcTextSize(primary).x + style.FramePadding.x * ActionButtonPadding, PrimaryButtonWidth * Scale());
    float secondaryWidth = std::max(ImGui::CalcTextSize(secondary).x + style.FramePadding.x * ActionButtonPadding, SecondaryButtonWidth * Scale());

    int action = ActionNone;
    Theme::PushPrimaryButton();
    if (ImGui::Button(primary, ImVec2(primaryWidth, height)))
        action = ActionPrimary;
    Theme::PopButton();

    ImGui::SameLine();
    Theme::PushSecondaryButton();
    if (ImGui::Button(secondary, ImVec2(secondaryWidth, height)))
        action = ActionSecondary;
    Theme::PopButton();

    if (status.kind != StatusKind::None || !status.text.empty())
    {
        ImGui::SameLine(0.0f, style.ItemSpacing.x * StatusGapScale);
        float y = ImGui::GetCursorPosY();
        ImGui::SetCursorPosY(y + (height - ImGui::GetTextLineHeight()) * 0.5f);
        StatusText(status);
    }
    return action;
}

// the tick / cross line next to the buttons. long errors get cut off with ... and the full text shows on hover
void Application::StatusText(const Status& status)
{
    const char* prefix = "";
    ImVec4 color = ImGui::GetStyle().Colors[ImGuiCol_TextDisabled];
    if (status.kind == StatusKind::Success)
    {
        prefix = "\xE2\x9C\x93  ";
        color = ImVec4(0.85f, 0.85f, 0.85f, 1.0f);
    }
    else if (status.kind == StatusKind::Failure)
    {
        prefix = "\xE2\x9C\x95  ";
        color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
    }

    std::string text = prefix + status.text;
    float available = ImGui::GetContentRegionAvail().x;
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    if (ImGui::CalcTextSize(text.c_str()).x <= available)
    {
        ImGui::TextUnformatted(text.c_str());
    }
    else
    {
        ImVec2 position = ImGui::GetCursorScreenPos();
        float lineHeight = ImGui::GetTextLineHeight();
        ImGui::RenderTextEllipsis(ImGui::GetWindowDrawList(), position, ImVec2(position.x + available, position.y + lineHeight), position.x + available, text.c_str(), nullptr, nullptr);
        ImGui::Dummy(ImVec2(available, lineHeight));
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("%s", status.text.c_str());
    }
    ImGui::PopStyleColor();
}
