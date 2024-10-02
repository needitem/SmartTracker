#include "WindowManager.h"
#include <windows.h>

// Callback function for EnumWindows
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    // Buffer to hold the window title
    wchar_t title[256];
    if (GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t)) == 0)
    {
        return TRUE; // Skip windows without titles
    }

    // Check if window is visible
    if (!IsWindowVisible(hwnd))
    {
        return TRUE; // Skip invisible windows
    }

    // Create a WindowInfo object and add it to the vector
    std::vector<WindowInfo>* windows = reinterpret_cast<std::vector<WindowInfo>*>(lParam);
    WindowInfo info;
    info.hwnd = hwnd;
    info.windowTitle = std::wstring(title);
    windows->push_back(info);

    return TRUE; // Continue enumeration
}

// Retrieves all top-level windows
std::vector<WindowInfo> WindowManager::GetTopLevelWindows()
{
    std::vector<WindowInfo> windows;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&windows));
    return windows;
}