#pragma once

#include <vector>
#include <string>
#include <windows.h>

// Structure to hold window information
struct WindowInfo {
    HWND hwnd;
    std::wstring windowTitle;
};

// Class to manage window listings
class WindowManager {
public:
    // Retrieves all top-level windows
    std::vector<WindowInfo> GetTopLevelWindows();
};