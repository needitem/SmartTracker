// Macro/KeyboardInput.h
#ifndef KEYBOARDINPUT_H
#define KEYBOARDINPUT_H

#include <windows.h>

class KeyboardInput
{
public:
    KeyboardInput();
    ~KeyboardInput();

    // 키보드 후킹을 시작합니다.
    bool StartHook();

    // 키보드 후킹을 중지합니다.
    void StopHook();

private:
    // 후크 프로시저
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

    // 후크 핸들러
    HHOOK hHook;
};

#endif // KEYBOARDINPUT_H