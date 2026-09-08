#pragma once
#include <cstdint>

namespace ObfHook
{
    enum class Form
    {
        Ff25 = 0,
        MovReg = 1,
        LeaReg = 2,
        E9Mod = 3,
        Ff25Heap = 4,
        Ff15Call = 5,
    };

    Form PickRandomForm();

    struct Hook
    {
        uint8_t* target = nullptr;
        int      cover  = 0;
        Form     form   = Form::Ff25;
        uint8_t  backup[64] = {};
        void*    tramp  = nullptr;
        void*    aux    = nullptr;
    };

    bool Create(Hook* h, void* target, void* handler, Form form);
    void Remove(Hook* h);
}
