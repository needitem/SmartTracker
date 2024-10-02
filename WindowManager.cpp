#include "WindowManager.h"
#include <windows.h>
#include <sstream>

// Callback function for EnumWindows
BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam)
{
    if (IsWindowVisible(hwnd) && GetWindowTextLengthW(hwnd) > 0)
    {
        int length = GetWindowTextLengthW(hwnd);
        std::wstring title(length, L'\0');
        GetWindowTextW(hwnd, &title[0], length + 1);

        std::vector<WindowInfo>* pWindows = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
        WindowInfo wi;
        wi.hwnd = hwnd;
        wi.windowTitle = title;
        pWindows->emplace_back(wi);

        // Debug logging
        std::wstringstream ss;
        ss << L"Added window handle: " << hwnd << L", Title: " << title << std::endl;
        OutputDebugStringW(ss.str().c_str());
    }
    return TRUE; // Continue enumeration
}

std::vector<WindowInfo> WindowManager::GetTopLevelWindows()
{
    std::vector<WindowInfo> windows;
    EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&windows));
    return windows;
}