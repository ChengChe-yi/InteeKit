#pragma once
#include <cstdint>

namespace ObfHook
{
    // 混淆形态族（编码细节见 cpp）：
    //   Ff25    FF 25 <disp32> + <abs64>（RIP 相对间接跳）
    //   MovReg  mov rX,imm64; jmp rX（X ∈ volatile 集）
    //   LeaReg  lea rX,[rip+disp32]; jmp rX（模块内可达时）
    enum class Form { Ff25 = 0, MovReg = 1, LeaReg = 2 };

    // 随机选取一个形态族（每次启动/每个 hook 点独立随机）。
    Form PickRandomForm();

    struct Hook
    {
        uint8_t* target = nullptr;
        int      cover  = 0;         // 实际搬移字节数（指令边界）
        Form     form   = Form::Ff25;
        uint8_t  backup[64] = {};
        void*    tramp  = nullptr;   // 原函数替身（搬移指令 + 修正 + 跳回）
    };

    // 安装：hde64 通用指令切分 + RIP-rel/跳转修正（参考 MinHook trampoline
    // 逻辑），不依赖固定 prologue 模板。失败返回 false 且不写任何字节。
    bool Create(Hook* h, void* target, void* handler, Form form);

    // 摘除：冻结线程 → 恢复原字节 → 解冻 → 释放 trampoline。幂等。
    void Remove(Hook* h);
}
