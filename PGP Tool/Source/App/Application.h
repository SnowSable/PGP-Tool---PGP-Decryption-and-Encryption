#pragma once

#include "ProfileStore.h"
#include "SecureText.h"
#include "Theme.h"

#include <string>

class Application
{
public:
    explicit Application(const Theme::Fonts& fonts);
    ~Application();

    Application(const Application&) = delete;
    Application& operator=(const Application&) = delete;

    void Render();

private:
    enum class StatusKind
    {
        None,
        Success,
        Failure
    };

    struct Status
    {
        std::string text;
        StatusKind kind = StatusKind::None;
    };

    void RenderEncryptTab();
    void RenderDecryptTab();
    void RenderProfileTab();
    void RenderPassphrasePopup();
    void RenderClearPopup();

    void Encrypt();
    void Decrypt();
    void UseSavedKey();
    void SaveProfile();
    void ClearProfile();
    void ResetEncrypt();
    void ResetDecrypt();

    void Label(const char* text);
    bool Header(const char* label, float width, const char* button, const char* widestButton, bool enabled);
    void TextBox(const char* id, std::string& text, float width, float height, bool readOnly, bool mono, const char* placeholder);
    void TextBox(const char* id, SecureText& text, float width, float height, bool mono, const char* placeholder);
    void Placeholder(bool empty, float width, const char* placeholder);
    bool BeginModal(const char* name, bool requested);
    void OutputPanel(const char* id, const char* label, std::string& text, double& copiedAt, float height, bool mono, const char* placeholder);
    int ActionButtons(const char* primary, const char* secondary, const Status& status);
    void StatusText(const Status& status);

    Theme::Fonts fonts;

    std::string plainMessage;
    std::string publicKey;
    std::string encryptedOutput;
    Status encryptStatus;
    double encryptCopiedAt = -10.0;

    std::string encryptedMessage;
    SecureText privateKey;
    std::string decryptedOutput;
    Status decryptStatus;
    double decryptCopiedAt = -10.0;

    SecureText passphrase;
    std::string passphraseError;
    bool passphraseRequested = false;
    bool focusPassphrase = false;

    Profile profile;
    Status profileStatus;
    double profileCopiedAt = -10.0;
    bool hasSavedProfile = false;
    bool hasSavedPrivateKey = false;
    bool clearRequested = false;
};
