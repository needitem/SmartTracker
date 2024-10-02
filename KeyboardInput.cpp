// Macro/KeyboardInput.cpp
#include "KeyboardInput.h"
#include <iostream>
#include <windows.h>

// 정적 변수로 현재 객체를 가리키는 포인터를 저장합니다.
static KeyboardInput *g_pThis = nullptr;

KeyboardInput::KeyboardInput() : hHook(NULL)
{
    g_pThis = this;
}

KeyboardInput::~KeyboardInput()
{
    StopHook();
    g_pThis = nullptr;
}

bool KeyboardInput::StartHook()
{
    if (hHook == NULL)
    {
        // WH_KEYBOARD_LL는 저수준 키보드 후크입니다.
        hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
        if (hHook == NULL)
        {
            std::cerr << "키보드 후크 설정에 실패했습니다." << std::endl;
            return false;
        }
    }
    return true;
}

void KeyboardInput::StopHook()
{
    if (hHook != NULL)
    {
        UnhookWindowsHookEx(hHook);
        hHook = NULL;
    }
}

// 정적 후크 프로시저
LRESULT CALLBACK KeyboardInput::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
        KBDLLHOOKSTRUCT *pKbDllHookStruct = reinterpret_cast<KBDLLHOOKSTRUCT *>(lParam);
        switch (wParam)
        {
        case WM_KEYDOWN:
        case WM_SYSKEYDOWN:
            std::cout << "키 pressed: " << pKbDllHookStruct->vkCode << std::endl;
            break;
        case WM_KEYUP:
        case WM_SYSKEYUP:
            std::cout << "키 released: " << pKbDllHookStruct->vkCode << std::endl;
            break;
        default:
            break;
        }
    }

    // 다음 후크 프로시저로 메시지를 전달합니다.
    return CallNextHookEx(g_pThis->hHook, nCode, wParam, lParam);
}