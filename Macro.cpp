#include "Macro.h"
#include "WindowManager.h"
#include "KeyboardInput.h"
#include "CaptureScreen.h" // Added include for CaptureScreen
#include <map>
#include <sstream>
#include <vector>
#include <windows.h>
#include <thread>
#include <atomic>
#include <mutex>

// Define custom Windows message
#define WM_WINDOW_NAME_UPDATED (WM_USER + 1)

// Global variables
HINSTANCE hInst;
HWND hControlPanel;
HWND hSelectorWindow = NULL;
KeyboardInput* g_keyboardInput = nullptr;

// Map to store window index and HWND
std::map<int, HWND> g_WindowMap;

// Atomic flags to control the threads
std::atomic<bool> g_OCRThreadRunning(false);
std::atomic<bool> g_InputThreadRunning(false);

// Threads
std::thread g_OCRThread;
std::thread g_InputThread;

// Store OCR text
std::wstring g_ocrText;
std::mutex g_ocrTextMutex;

// Selected HWND
HWND g_SelectedHWND = NULL;

// IDs for control buttons and static texts
#define ID_BUTTON_STOP             1001
#define ID_BUTTON_RESUME           1002
#define ID_BUTTON_QUIT             1003
#define ID_BUTTON_SELECT_WINDOW    1004
#define ID_STATIC_WINDOW_NAME      1005
#define ID_STATIC_OCR_TEXT         1006
#define ID_TIMER_UPDATE_OCR        1007

// Function declarations
LRESULT CALLBACK ControlPanelWindowProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK SelectorWindowProc(HWND, UINT, WPARAM, LPARAM);
void PopulateWindowList(HWND hListBox);
void SendStringToWindow(HWND hwnd, const std::wstring& str);
std::wstring GetTextFromWindowUsingOCR(HWND hwnd); // Ensure this is implemented
void OCRWorker(HWND hwnd);
void InputWorker(HWND hwnd);
void StartOCRAndInputThreads(HWND hwnd);
void StopThreads();
void CreateControlPanelWindow();
void CreateSelectorWindow();

// Function to populate the list box with window titles
void PopulateWindowList(HWND hListBox)
{
    WindowManager wm;
    std::vector<WindowInfo> windows = wm.GetTopLevelWindows();

    // Clear existing items in the list box
    SendMessageW(hListBox, LB_RESETCONTENT, 0, 0);

    for (const auto& win : windows)
    {
        // Add window title to list box and get the actual index
        LRESULT addResult = SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)win.windowTitle.c_str());
        if (addResult != LB_ERR && addResult != LB_ERRSPACE)
        {
            int actualIndex = static_cast<int>(addResult);

            // Store HWND as item data
            SendMessageW(hListBox, LB_SETITEMDATA, actualIndex, (LPARAM)win.hwnd);

            // Add to map
            g_WindowMap[actualIndex] = win.hwnd;

            // Debug logging
            std::wstringstream ss;
            ss << L"List index: " << actualIndex << L", HWND: " << win.hwnd << L", Title: " << win.windowTitle << std::endl;
            OutputDebugStringW(ss.str().c_str());
        }
    }

    // Debug logging
    OutputDebugStringW(L"Inserted window list into list box.\n");
}

// Function to send a string to a window using SendInput
void SendStringToWindow(HWND hwnd, const std::wstring& str)
{
    if (hwnd == NULL)
        return;

    // Validate the window handle
    if (!IsWindow(hwnd))
    {
        std::wstringstream ss;
        ss << L"Invalid HWND: " << hwnd << std::endl;
        OutputDebugStringW(ss.str().c_str());
        MessageBoxW(NULL, L"The selected window handle is invalid.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Bring the window to the foreground
    if (!SetForegroundWindow(hwnd))
    {
        MessageBoxW(NULL, L"Cannot bring the target window to the foreground.", L"Error", MB_OK | MB_ICONERROR);
        OutputDebugStringW(L"SetForegroundWindow failed.\n");
        return;
    }

    // Prepare input events
    std::vector<INPUT> inputs;
    for (wchar_t ch : str)
    {
        INPUT inputDown = { 0 };
        inputDown.type = INPUT_KEYBOARD;
        inputDown.ki.wScan = ch;
        inputDown.ki.dwFlags = KEYEVENTF_UNICODE;
        inputs.push_back(inputDown);

        INPUT inputUp = { 0 };
        inputUp.type = INPUT_KEYBOARD;
        inputUp.ki.wScan = ch;
        inputUp.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        inputs.push_back(inputUp);
    }

    // Send the input events
    if (!SendInput(static_cast<UINT>(inputs.size()), inputs.data(), sizeof(INPUT)))
    {
        OutputDebugStringW(L"SendInput failed.\n");
    }
}

// OCR Worker thread function
void OCRWorker(HWND hwnd)
{
    g_OCRThreadRunning = true;
    while (g_OCRThreadRunning)
    {
        std::wstring ocrResult = GetTextFromWindowUsingOCR(hwnd);
        {
            std::lock_guard<std::mutex> lock(g_ocrTextMutex);
            g_ocrText = ocrResult;
        }

        // Notify the Control Panel to update the OCR text display
        PostMessageW(hControlPanel, WM_WINDOW_NAME_UPDATED, 0, 0);

        // Sleep for a certain interval before next OCR
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

// Input Worker thread function
void InputWorker(HWND hwnd)
{
    g_InputThreadRunning = true;
    while (g_InputThreadRunning)
    {
        // Example: Send the OCR text to the selected window every 10 seconds
        std::wstring textToSend;
        {
            std::lock_guard<std::mutex> lock(g_ocrTextMutex);
            textToSend = g_ocrText;
        }

        // Sleep for a certain interval before next input
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}

// Starts OCR and Input threads
void StartOCRAndInputThreads(HWND hwnd)
{
    if (!g_OCRThreadRunning)
    {
        g_OCRThread = std::thread(OCRWorker, hwnd);
    }

    if (!g_InputThreadRunning)
    {
        g_InputThread = std::thread(InputWorker, hwnd);
    }
}

// Stops OCR and Input threads
void StopThreads()
{
    if (g_OCRThreadRunning)
    {
        g_OCRThreadRunning = false;
        if (g_OCRThread.joinable())
            g_OCRThread.join();
    }

    if (g_InputThreadRunning)
    {
        g_InputThreadRunning = false;
        if (g_InputThread.joinable())
            g_InputThread.join();
    }
}

// Control Panel Window Procedure
LRESULT CALLBACK ControlPanelWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static HWND hSelectWindowButton;
    static HWND hWindowNameStatic;
    static HWND hOCRTextStatic;

    switch (uMsg)
    {
    case WM_CREATE:
    {
        // Create control buttons
        hSelectWindowButton = CreateWindowW(
            L"BUTTON",
            L"Select Window",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            10, 10, 150, 30,
            hwnd,
            (HMENU)ID_BUTTON_SELECT_WINDOW,
            hInst,
            NULL
        );

        CreateWindowW(
            L"BUTTON",
            L"Stop",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            170, 10, 150, 30,
            hwnd,
            (HMENU)ID_BUTTON_STOP,
            hInst,
            NULL
        );

        CreateWindowW(
            L"BUTTON",
            L"Resume",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            330, 10, 150, 30,
            hwnd,
            (HMENU)ID_BUTTON_RESUME,
            hInst,
            NULL
        );

        CreateWindowW(
            L"BUTTON",
            L"Quit",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            490, 10, 150, 30,
            hwnd,
            (HMENU)ID_BUTTON_QUIT,
            hInst,
            NULL
        );

        // Create static controls for window name and OCR text
        hWindowNameStatic = CreateWindowW(
            L"STATIC",
            L"",
            WS_VISIBLE | WS_CHILD,
            10, 50, 630, 30,
            hwnd,
            (HMENU)ID_STATIC_WINDOW_NAME,
            hInst,
            NULL
        );

        hOCRTextStatic = CreateWindowW(
            L"STATIC",
            L"",
            WS_VISIBLE | WS_CHILD | SS_LEFT | SS_NOTIFY | WS_VSCROLL,
            10, 90, 630, 200,
            hwnd,
            (HMENU)ID_STATIC_OCR_TEXT,
            hInst,
            NULL
        );

        // Initially hide the static controls
        ShowWindow(hWindowNameStatic, SW_HIDE);
        ShowWindow(hOCRTextStatic, SW_HIDE);

        // Debug logging
        OutputDebugStringW(L"Control Panel window created.\n");
    }
    break;
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case ID_BUTTON_SELECT_WINDOW:
        {
            // Create the Selector window
            CreateSelectorWindow();
        }
        break;
        case ID_BUTTON_STOP:
        {
            // Stop the threads
            StopThreads();
        }
        break;
        case ID_BUTTON_RESUME:
        {
            if (g_SelectedHWND != NULL && IsWindow(g_SelectedHWND))
            {
                // Resume the threads
                StartOCRAndInputThreads(g_SelectedHWND);
            }
            else
            {
                MessageBoxW(NULL, L"No valid window selected to resume.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        break;
        case ID_BUTTON_QUIT:
        {
            // Ensure threads are stopped before quitting
            StopThreads();
            PostQuitMessage(0);
        }
        break;
        }
    }
    break;
    case WM_WINDOW_NAME_UPDATED:
    {
        // Update the window name static control
        wchar_t windowTitle[256];
        GetWindowTextW(g_SelectedHWND, windowTitle, 256);
        SetWindowTextW(hWindowNameStatic, windowTitle);
        ShowWindow(hWindowNameStatic, SW_SHOW);

        // Update the OCR text static control
        {
            std::lock_guard<std::mutex> lock(g_ocrTextMutex);
            SetWindowTextW(hOCRTextStatic, g_ocrText.c_str());
        }
        ShowWindow(hOCRTextStatic, SW_SHOW);

        // Replace the "Select Window" button label with the window name
        // Hide the Select Window button and show the window name instead
        ShowWindow(hSelectWindowButton, SW_HIDE);
    }
    break;
    case WM_CLOSE:
    {
        // Ensure threads are stopped before closing
        StopThreads();
        DestroyWindow(hwnd);
    }
    break;
    case WM_DESTROY:
    {
        PostQuitMessage(0);
        return 0;
    }
    break;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// Selector Window Procedure
LRESULT CALLBACK SelectorWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static HWND hListBox;
    switch (uMsg)
    {
    case WM_CREATE:
    {
        // Create the list box
        hListBox = CreateWindowW(
            L"LISTBOX",
            NULL,
            WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_BORDER,
            10, 10, 460, 300,
            hwnd,
            (HMENU)1, // ID for list box
            hInst,
            NULL
        );

        // Populate the list box
        PopulateWindowList(hListBox);

        // Debug logging
        OutputDebugStringW(L"Selector window created with list box.\n");
    }
    break;
    case WM_COMMAND:
    {
        if (LOWORD(wParam) == 1 && HIWORD(wParam) == LBN_SELCHANGE)
        {
            // Get selected index
            LRESULT selectedIndexResult = SendMessageW(hListBox, LB_GETCURSEL, 0, 0);
            int selectedIndex = static_cast<int>(selectedIndexResult);

            if (selectedIndex == LB_ERR)
            {
                // Invalid selection
                OutputDebugStringW(L"No selection or invalid selection.\n");
                return 0;
            }

            // Get HWND from item data
            LRESULT selectedHWNDResult = SendMessageW(hListBox, LB_GETITEMDATA, selectedIndex, 0);
            HWND selectedHWND = reinterpret_cast<HWND>(selectedHWNDResult);

            if (selectedHWND != NULL && IsWindow(selectedHWND))
            {
                g_SelectedHWND = selectedHWND;
                OutputDebugStringW(L"Selected HWND is valid. Starting threads.\n");

                // Start OCR and Input threads
                StartOCRAndInputThreads(g_SelectedHWND);

                // Notify Control Panel to update UI
                PostMessageW(hControlPanel, WM_WINDOW_NAME_UPDATED, 0, 0);

                // Close the Selector window without terminating the app
                DestroyWindow(hwnd);
            }
            else
            {
                // Debug logging
                OutputDebugStringW(L"Selected HWND is invalid.\n");
                MessageBoxW(NULL, L"The selected window handle is invalid.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
    }
    break;
    case WM_CLOSE:
    {
        DestroyWindow(hwnd);
    }
    break;
    case WM_DESTROY:
    {
        // Do not call PostQuitMessage here to keep the main message loop running
        hSelectorWindow = NULL; // Reset the Selector window handle
        return 0;
    }
    break;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// Creates the Control Panel window
void CreateControlPanelWindow()
{
    // Register window class
    const wchar_t CLASS_NAME[] = L"ControlPanelWindowClass";

    WNDCLASSW wc = { };

    wc.lpfnWndProc = ControlPanelWindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;

    RegisterClassW(&wc);

    // Create the window
    hControlPanel = CreateWindowExW(
        0,                              // Optional window styles.
        CLASS_NAME,                     // Window class
        L"Control Panel",    // Window text
        WS_OVERLAPPEDWINDOW,            // Window style

        // Size and position
        CW_USEDEFAULT, CW_USEDEFAULT, 660, 300,

        NULL,       // Parent window    
        NULL,       // Menu
        hInst,  // Instance handle
        NULL        // Additional application data
    );

    if (hControlPanel == NULL)
    {
        OutputDebugStringW(L"Failed to create Control Panel window.\n");
        return;
    }

    ShowWindow(hControlPanel, SW_SHOW);
}

// Creates the Selector window
void CreateSelectorWindow()
{
    if (hSelectorWindow != NULL)
    {
        // Selector window is already open
        return;
    }

    // Register window class
    const wchar_t CLASS_NAME[] = L"SelectorWindowClass";

    WNDCLASSW wc = { };

    wc.lpfnWndProc = SelectorWindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = CLASS_NAME;

    RegisterClassW(&wc);

    // Create the window
    hSelectorWindow = CreateWindowExW(
        0,                              // Optional window styles.
        CLASS_NAME,                     // Window class
        L"Select Window",    // Window text
        WS_OVERLAPPEDWINDOW,            // Window style

        // Size and position
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 350,

        NULL,       // Parent window    
        NULL,       // Menu
        hInst,  // Instance handle
        NULL        // Additional application data
    );

    if (hSelectorWindow == NULL)
    {
        OutputDebugStringW(L"Failed to create Selector window.\n");
        return;
    }

    ShowWindow(hSelectorWindow, SW_SHOW);
}

// WinMain: Entry point for Windows applications
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    hInst = hInstance;

    // Create the Control Panel window
    CreateControlPanelWindow();

    // Run the message loop
    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}