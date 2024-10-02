#pragma once

#include <string>
#include <windows.h>

// Function declarations
void SendStringToWindow(HWND hwnd, const std::wstring& str);
void PopulateWindowList(HWND hListBox);