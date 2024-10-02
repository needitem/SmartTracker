#include "Macro.h"
#include "WindowManager.h"
#include "KeyboardInput.h" // Ensure this header is correctly implemented
#include <map>
#include <sstream>
#include <vector>
#include <windows.h>

// Global variables
HINSTANCE hInst;
HWND hListBox;
KeyboardInput* g_keyboardInput = nullptr;

// Map to store window index and HWND
std::map<int, HWND> g_WindowMap;

// Function declarations
LRESULT CALLBACK WindowProc(HWND, UINT, WPARAM, LPARAM);

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
        int actualIndex = static_cast<int>(SendMessageW(hListBox, LB_ADDSTRING, 0, (LPARAM)win.windowTitle.c_str()));
        if (actualIndex != LB_ERR && actualIndex != LB_ERRSPACE)
        {
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

    // Send input events
    UINT sent = SendInput(static_cast<UINT>(inputs.size()), inputs.data(), sizeof(INPUT));

    // Debug logging: SendInput result
    std::wstringstream ss;
    ss << L"SendInput called: Requested inputs: " << inputs.size() << L", Sent inputs: " << sent << std::endl;
    OutputDebugStringW(ss.str().c_str());

    if (sent != inputs.size())
    {
        OutputDebugStringW(L"SendInput failed: Mismatch in input count.\n");
    }
}

// Window Procedure definition
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CREATE:
    {
        // Create list box
        hListBox = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            L"LISTBOX",
            NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_STANDARD,
            10, 10, 360, 400,
            hwnd,
            (HMENU)1,
            hInst,
            NULL
        );

        // Populate the list box with window titles
        PopulateWindowList(hListBox);

        // Debug logging: Completion message
        OutputDebugStringW(L"Window list populated.\n");
    }
    break;
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) // List box ID
        {
            if (HIWORD(wParam) == LBN_SELCHANGE) // Selection change
            {
                int index = static_cast<int>(SendMessageW(hListBox, LB_GETCURSEL, 0, 0));
                if (index != LB_ERR)
                {
                    // Get HWND from item data
                    HWND selectedHWND = reinterpret_cast<HWND>(SendMessageW(hListBox, LB_GETITEMDATA, index, 0));

                    // Debug logging
                    std::wstringstream ss;
                    ss << L"Selected index: " << index << L", HWND: " << selectedHWND << std::endl;
                    OutputDebugStringW(ss.str().c_str());

                    if (selectedHWND == NULL || !IsWindow(selectedHWND))
                    {
                        // Show error message
                        MessageBoxW(hwnd, L"Cannot find the handle of the selected window.", L"Error", MB_OK | MB_ICONERROR);

                        // Debug logging
                        OutputDebugStringW(L"Selected HWND is invalid.\n");
                        return 0;
                    }

                    // Send "asdf" string to selected window
                    SendStringToWindow(selectedHWND, L"asdf");

                    // Close the selector window
                    DestroyWindow(hwnd);
                }
                else
                {
                    // Debug logging
                    OutputDebugStringW(L"Invalid selection index.\n");
                }
            }
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// WinMain: Entry point for Windows applications
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
    hInst = hInstance;

    // Register the window class
    const wchar_t CLASS_NAME[] = L"MacroWindowClass";

    WNDCLASSW wc = { };

    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    RegisterClassW(&wc);

    // Create the window
    HWND hwnd = CreateWindowExW(
        0,                              // Optional window styles.
        CLASS_NAME,                     // Window class
        L"Macro Application",          // Window text
        WS_OVERLAPPEDWINDOW,            // Window style

        // Size and position
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 450,

        NULL,       // Parent window    
        NULL,       // Menu
        hInstance,  // Instance handle
        NULL        // Additional application data
    );

    if (hwnd == NULL)
    {
        return 0;
    }

    ShowWindow(hwnd, nCmdShow);

    // Run the message loop
    MSG msg = { };
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}