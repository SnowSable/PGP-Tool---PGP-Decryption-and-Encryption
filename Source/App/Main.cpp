#include "Application.h"
#include "Theme.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <dwmapi.h>

#include <algorithm>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace
{
    constexpr wchar_t WindowClass[] = L"PgpToolWindow";
    constexpr wchar_t WindowTitle[] = L"PGP Tool";
    constexpr int BaseWidth = 1120;
    constexpr int BaseHeight = 800;
    constexpr int MinimumWidth = 760;
    constexpr int MinimumHeight = 620;

    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* deviceContext = nullptr;
    IDXGISwapChain* swapChain = nullptr;
    ID3D11RenderTargetView* renderTarget = nullptr;
    UINT resizeWidth = 0;
    UINT resizeHeight = 0;
    bool swapChainOccluded = false;
    float dpiScale = 1.0f;
    float pendingDpiScale = 0.0f;

    void CreateRenderTarget()
    {
        ID3D11Texture2D* backBuffer = nullptr;
        if (SUCCEEDED(swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
        {
            device->CreateRenderTargetView(backBuffer, nullptr, &renderTarget);
            backBuffer->Release();
        }
    }

    void CleanupRenderTarget()
    {
        if (renderTarget)
        {
            renderTarget->Release();
            renderTarget = nullptr;
        }
    }

    bool CreateDevice(HWND window)
    {
        DXGI_SWAP_CHAIN_DESC description = {};
        description.BufferCount = 2;
        description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        description.BufferDesc.RefreshRate.Numerator = 60;
        description.BufferDesc.RefreshRate.Denominator = 1;
        description.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        description.OutputWindow = window;
        description.SampleDesc.Count = 1;
        description.Windowed = TRUE;
        description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
        D3D_FEATURE_LEVEL level;
        HRESULT result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &description, &swapChain, &device, &level, &deviceContext);
        if (result == DXGI_ERROR_UNSUPPORTED)
            result = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &description, &swapChain, &device, &level, &deviceContext);
        if (FAILED(result))
            return false;

        CreateRenderTarget();
        return true;
    }

    void CleanupDevice()
    {
        CleanupRenderTarget();
        if (swapChain)
        {
            swapChain->Release();
            swapChain = nullptr;
        }
        if (deviceContext)
        {
            deviceContext->Release();
            deviceContext = nullptr;
        }
        if (device)
        {
            device->Release();
            device = nullptr;
        }
    }

    // windows 11 lets you colour the title bar, this makes it black to match. on win 10 it just does nothing
    void StyleTitleBar(HWND window)
    {
        BOOL dark = TRUE;
        DwmSetWindowAttribute(window, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
        COLORREF black = RGB(0, 0, 0);
        COLORREF white = RGB(255, 255, 255);
        COLORREF border = RGB(40, 40, 40);
        DwmSetWindowAttribute(window, DWMWA_CAPTION_COLOR, &black, sizeof(black));
        DwmSetWindowAttribute(window, DWMWA_TEXT_COLOR, &white, sizeof(white));
        DwmSetWindowAttribute(window, DWMWA_BORDER_COLOR, &border, sizeof(border));
    }

    LRESULT WINAPI WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam))
            return true;

        switch (message)
        {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;
            resizeWidth = static_cast<UINT>(LOWORD(lParam));
            resizeHeight = static_cast<UINT>(HIWORD(lParam));
            return 0;
        case WM_GETMINMAXINFO:
        {
            auto info = reinterpret_cast<MINMAXINFO*>(lParam);
            info->ptMinTrackSize.x = static_cast<LONG>(MinimumWidth * dpiScale);
            info->ptMinTrackSize.y = static_cast<LONG>(MinimumHeight * dpiScale);
            return 0;
        }
        // moved onto a monitor with different scaling, resize the window and redo the theme next frame (line 248)
        case WM_DPICHANGED:
        {
            pendingDpiScale = HIWORD(wParam) / 96.0f;
            auto suggested = reinterpret_cast<const RECT*>(lParam);
            SetWindowPos(window, nullptr, suggested->left, suggested->top, suggested->right - suggested->left, suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);
            return 0;
        }
        case WM_ERASEBKGND:
            return 1;
        case WM_SYSCOMMAND:
            if ((wParam & 0xFFF0) == SC_KEYMENU)
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand)
{
    ImGui_ImplWin32_EnableDpiAwareness();
    dpiScale = ImGui_ImplWin32_GetDpiScaleForMonitor(MonitorFromPoint(POINT{ 0, 0 }, MONITOR_DEFAULTTOPRIMARY));

    WNDCLASSEXW windowClass = {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_CLASSDC;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    windowClass.lpszClassName = WindowClass;
    RegisterClassExW(&windowClass);

    int width = static_cast<int>(BaseWidth * dpiScale);
    int height = static_cast<int>(BaseHeight * dpiScale);
    RECT workArea = {};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);
    width = std::min(width, static_cast<int>(workArea.right - workArea.left));
    height = std::min(height, static_cast<int>(workArea.bottom - workArea.top));
    int x = workArea.left + (workArea.right - workArea.left - width) / 2;
    int y = workArea.top + (workArea.bottom - workArea.top - height) / 2;

    HWND window = CreateWindowExW(0, WindowClass, WindowTitle, WS_OVERLAPPEDWINDOW, x, y, width, height, nullptr, nullptr, instance, nullptr);
    if (!window)
        return 1;
    StyleTitleBar(window);

    if (!CreateDevice(window))
    {
        CleanupDevice();
        DestroyWindow(window);
        UnregisterClassW(WindowClass, instance);
        MessageBoxW(nullptr, L"Direct3D 11 could not be initialised.", WindowTitle, MB_ICONERROR);
        return 1;
    }

    ShowWindow(window, showCommand);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    Theme::Apply(dpiScale);
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(device, deviceContext);
    Theme::Fonts fonts = Theme::LoadFonts();

    {
        // scoped so the app (and all its wiped buffers) dies before imgui gets shut down
        Application application(fonts);
        const float clearColor[4] = { 0.0f, 0.0f, 0.0f, 1.0f };
        bool running = true;

        while (running)
        {
            // when the window isn't focused we chill out a bit so it doesn't burn cpu in the background
            if (GetForegroundWindow() != window)
                MsgWaitForMultipleObjects(0, nullptr, FALSE, 50, QS_ALLINPUT);

            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
                if (message.message == WM_QUIT)
                    running = false;
            }
            if (!running)
                break;

            if (swapChainOccluded && swapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                Sleep(10);
                continue;
            }
            swapChainOccluded = false;

            if (resizeWidth != 0 && resizeHeight != 0)
            {
                CleanupRenderTarget();
                swapChain->ResizeBuffers(0, resizeWidth, resizeHeight, DXGI_FORMAT_UNKNOWN, 0);
                resizeWidth = 0;
                resizeHeight = 0;
                CreateRenderTarget();
            }

            if (pendingDpiScale > 0.0f)
            {
                dpiScale = pendingDpiScale;
                pendingDpiScale = 0.0f;
                Theme::Apply(dpiScale);
            }

            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            application.Render();

            ImGui::Render();
            deviceContext->OMSetRenderTargets(1, &renderTarget, nullptr);
            deviceContext->ClearRenderTargetView(renderTarget, clearColor);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            HRESULT result = swapChain->Present(1, 0);
            swapChainOccluded = result == DXGI_STATUS_OCCLUDED;
        }
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDevice();
    DestroyWindow(window);
    UnregisterClassW(WindowClass, instance);
    return 0;
}
