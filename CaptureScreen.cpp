#include "CaptureScreen.h"
#include <iostream>
#include <leptonica/allheaders.h>
#include <tesseract/baseapi.h>
#include <cstdio> // For std::remove
#include <vector>
#include <windows.h>

// Performs OCR on the capture.png file and returns the recognized text as a std::wstring.
std::wstring PerformOCROnCapturePNG()
{
    // Load the image from capture.png
    Pix* image = pixRead("capture.png");
    if (!image)
    {
        OutputDebugStringW(L"Failed to read capture.png for OCR.\n");
        return L"";
    }

    // Convert image to grayscale for better OCR accuracy
    Pix* grayImage = pixConvertTo8(image, 0);
    if (!grayImage)
    {
        OutputDebugStringW(L"Failed to convert image to grayscale.\n");
        pixDestroy(&image);
        return L"";
    }
    pixDestroy(&image); // Destroy the original Pix as it's no longer needed

    // Apply median filter to reduce noise
    Pix* denoisedImage = pixMedianFilter(grayImage, 3, 3);
    if (!denoisedImage)
    {
        OutputDebugStringW(L"Failed to apply median filter.\n");
        pixDestroy(&grayImage);
        return L"";
    }
    pixDestroy(&grayImage); // Destroy the grayscale image as it's no longer needed

    // Specify the path to tessdata
    std::wstring tessDataPath = L"C:\\Users\\p22418\\Desktop\\tesseract-5.4.1\\tessdata";
    std::wstring tessDataPathWithSlash = tessDataPath + L"\\"; // Add trailing backslash

    // Convert std::wstring to std::string using WideCharToMultiByte
    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, tessDataPathWithSlash.c_str(), -1, NULL, 0, NULL, NULL);
    if (bufferSize == 0)
    {
        OutputDebugStringW(L"Failed to get buffer size for tessdata path.\n");
        pixDestroy(&denoisedImage);
        return L"";
    }

    std::string tessDataPathNarrow(bufferSize, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, tessDataPathWithSlash.c_str(), -1, &tessDataPathNarrow[0], bufferSize, NULL, NULL) == 0)
    {
        OutputDebugStringW(L"Failed to convert tessdata path to narrow string.\n");
        pixDestroy(&denoisedImage);
        return L"";
    }

    // Initialize Tesseract OCR engine with the path to tessdata
    tesseract::TessBaseAPI tess;
    if (tess.Init(tessDataPathNarrow.c_str(), "kor+eng", tesseract::OEM_LSTM_ONLY))
    {
        OutputDebugStringW(L"Failed to initialize Tesseract.\n");
        pixDestroy(&denoisedImage);
        return L"";
    }

    // Configure Tesseract to handle mixed languages better
    tess.SetVariable("classify_bln_numeric_mode", "0");

    // Set the Page Segmentation Mode to automatic
    tess.SetPageSegMode(tesseract::PSM_AUTO);

    tess.SetImage(denoisedImage);
    tess.Recognize(0);
    const char* outText = tess.GetUTF8Text();
    if (!outText)
    {
        OutputDebugStringW(L"Failed to get OCR text.\n");
        tess.End();
        pixDestroy(&denoisedImage);
        return L"";
    }

    // Properly convert UTF-8 'outText' to std::wstring
    int len = MultiByteToWideChar(CP_UTF8, 0, outText, -1, NULL, 0);
    std::wstring result;
    if (len > 0)
    {
        std::wstring wstr(len - 1, L'\0'); // Exclude the null terminator
        MultiByteToWideChar(CP_UTF8, 0, outText, -1, &wstr[0], len - 1);
        result = wstr;
    }
    else
    {
        OutputDebugStringW(L"Failed to convert OCR output to wide string.\n");
        result = L"";
    }

    // Clean up
    tess.End();
    pixDestroy(&denoisedImage);
    free((void*)outText);

    return result;
}

// Captures the screenshot of the specified window and returns it as an HBITMAP.
// Returns nullptr if the capture fails.
HBITMAP CaptureWindowScreenshot(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    HDC hdcWindow = GetDC(hwnd);
    HDC hdcMemDC = CreateCompatibleDC(hdcWindow);

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcWindow, width, height);
    if (!hBitmap)
    {
        OutputDebugStringW(L"Failed to create compatible bitmap.\n");
        DeleteDC(hdcMemDC);
        ReleaseDC(hwnd, hdcWindow);
        return nullptr;
    }

    SelectObject(hdcMemDC, hBitmap);

    if (!BitBlt(hdcMemDC, 0, 0, width, height, hdcWindow, 0, 0, SRCCOPY | CAPTUREBLT))
    {
        OutputDebugStringW(L"BitBlt failed.\n");
        DeleteObject(hBitmap);
        hBitmap = nullptr;
    }

    DeleteDC(hdcMemDC);
    ReleaseDC(hwnd, hdcWindow);

    return hBitmap;
}

// Performs OCR on the provided HBITMAP and returns the recognized text as a std::wstring.
// Requires the HBITMAP to be saved as "capture.png" before calling this function.
std::wstring PerformOCROnBitmap(HBITMAP hBitmap)
{
    // Save HBITMAP as "capture.png"
    // Implement a function to save HBITMAP to a PNG file.
    // This can be done using GDI+ or another image library.
    // For simplicity, this step is omitted.

    // TODO: Implement saving HBITMAP to "capture.png"

    // After saving, perform OCR
    return PerformOCROnCapturePNG();
}

// Captures the window screenshot and performs OCR to retrieve the window text.
std::wstring GetTextFromWindowUsingOCR(HWND hwnd)
{
    HBITMAP hBitmap = CaptureWindowScreenshot(hwnd);
    if (!hBitmap)
    {
        OutputDebugStringW(L"Failed to capture window screenshot.\n");
        return L"";
    }

    std::wstring ocrText = PerformOCROnBitmap(hBitmap);

    DeleteObject(hBitmap);

    return ocrText;
}