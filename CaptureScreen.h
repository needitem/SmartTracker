#pragma once

#include <string>
#include <windows.h>
#include <leptonica/allheaders.h>

// Captures the screenshot of the specified window and returns it as an HBITMAP.
// Returns nullptr if the capture fails.
HBITMAP CaptureWindowScreenshot(HWND hwnd);

// Performs OCR on the provided HBITMAP and returns the recognized text as a std::wstring.
// Requires Tesseract OCR library to be integrated into the project.
std::wstring PerformOCROnBitmap(HBITMAP hBitmap);

// Captures the window screenshot and performs OCR to retrieve the window text.
std::wstring GetTextFromWindowUsingOCR(HWND hwnd);