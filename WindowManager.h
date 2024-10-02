#pragma once

#include <string>
#include <vector>
#include <windows.h>

// Structure to hold window information
struct WindowInfo
{
    HWND hwnd = NULL; // Initialized to NULL to prevent uninitialized variable warning
    std::wstring windowTitle;
};

// WindowManager class declaration
class WindowManager
{
public:
    // Retrieves all top-level windows
    std::vector<WindowInfo> GetTopLevelWindows();
};