#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include "../MinHook/src/hde/hde64.h"
#include "ObfHook.h"
#include <cstring>

namespace ObfHook
{
    // ==================================================================
    // 线程冻结（写入/恢复期间防半写态）
    // ==================================================================

    static int FreezeThreads(bool suspend)
    {
        const DWORD self = GetCurrentThreadId();
        const DWORD pid  = GetCurrentProcessId();

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;

        int n = 0;
        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);
        for (BOOL has = Thread32First(snap, &te); has; has = Thread32Next(snap, &te)) {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == self) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (!h) continue;
            if (suspend) {
                if (SuspendThread(h) != (DWORD)-1) ++n;
            } else {
                ResumeThread(h);
            }
            CloseHandle(h);
        }
        CloseHandle(snap);
        return n;
    }

    // ==================================================================
    // 通用 trampoline 构建（参考 MinHook trampoline.c）：
    //   从 target 头部逐条解码搬移；RIP-relative 数据访问重算 disp32；
    //   call/jmp/jcc 一律绝对化（跳板形式）；尾部绝对跳回 target+cover。
    // ==================================================================

    static constexpr int kMaxCover  = 64;

    static int NeedCover(Form form)
    {
        switch (form) {
        case Form::Ff25:
        case Form::Ff25Heap: return 14;
        case Form::MovReg:   return 12;
        case Form::LeaReg:   return 10;
        case Form::E9Mod:    return 6;    // E9(5B)+1B 垃圾，覆盖 6B 边界
        }
        return 14;
    }

    // 绝对跳板（MinHook 同款 x64 编码）：
    //   jmp [rip+0]  : FF 25 00000000 + addr          (14B)
    //   call [rip+2] : FF 15 00000002 EB 08 + addr    (16B，返回后跳越 addr)
    //   jcc 跳板     : 7x 0E FF 25 00000000 + addr    (16B)
    static int EmitJmpAbs(uint8_t* dst, uint64_t dest)
    {
        dst[0] = 0xFF; dst[1] = 0x25;
        dst[2] = dst[3] = dst[4] = dst[5] = 0;
        memcpy(dst + 6, &dest, 8);
        return 14;
    }
    static int EmitCallAbs(uint8_t* dst, uint64_t dest)
    {
        dst[0] = 0xFF; dst[1] = 0x15;
        dst[2] = 0x02; dst[3] = 0x00; dst[4] = 0x00; dst[5] = 0x00;
        dst[6] = 0xEB; dst[7] = 0x08;
        memcpy(dst + 8, &dest, 8);
        return 16;
    }
    static int EmitJccAbs(uint8_t* dst, uint64_t dest, int cc)
    {
        dst[0] = (uint8_t)(0x70 + cc); dst[1] = 0x0E;
        dst[2] = 0xFF; dst[3] = 0x25;
        dst[4] = dst[5] = dst[6] = dst[7] = 0;
        memcpy(dst + 8, &dest, 8);
        return 16;
    }

    static int BuildTrampoline(uint8_t* t, uint8_t* tramp, int need)
    {
        int oldPos = 0, newPos = 0;
        uint8_t inst[24];
        uint8_t absBuf[24];

        for (;;)
        {
            hde64s hs;
            const unsigned int cs = hde64_disasm(t + oldPos, &hs);
            if (!cs || (hs.flags & F_ERROR) || hs.len == 0)
                return -1;

            const int len = (int)hs.len;
            if (oldPos >= need)
                break;
            if (oldPos + len > kMaxCover)
                return -1;

            const uint8_t* srcP = t + oldPos;
            int copyLen = len;

            if ((hs.modrm & 0xC7) == 0x05)
            {
                // RIP-relative 数据访问：重算 disp32
                memcpy(inst, srcP, len);
                const uint32_t immLen = (hs.flags & 0x3C) >> 2;
                int32_t* rel = (int32_t*)(inst + len - (int)immLen - 4);
                const int64_t oldTgt = (int64_t)(srcP + len) + (int32_t)hs.disp.disp32;
                const int64_t newRip = (int64_t)(tramp + newPos + len);
                const int64_t nd = oldTgt - newRip;
                if (nd < INT32_MIN || nd > INT32_MAX)
                    return -1;                       // 修正后超 2GB：拒绝
                *rel = (int32_t)nd;
                srcP = inst;
            }
            else if (hs.opcode == 0xE8)
            {
                const uint64_t dest = (uint64_t)(srcP + len) + (uint32_t)hs.imm.imm32;
                copyLen = EmitCallAbs(absBuf, dest);
                srcP = absBuf;
            }
            else if (hs.opcode == 0xE9 || hs.opcode == 0xEB)
            {
                const uint64_t dest = (uint64_t)(srcP + len) +
                    (hs.opcode == 0xEB ? (uint64_t)(int64_t)(int8_t)hs.imm.imm8
                                       : (uint64_t)(int64_t)(int32_t)hs.imm.imm32);
                copyLen = EmitJmpAbs(absBuf, dest);
                srcP = absBuf;
            }
            else if ((hs.opcode == 0x0F && (hs.opcode2 & 0xF0) == 0x80) ||
                     (hs.opcode >= 0x70 && hs.opcode <= 0x7F))
            {
                const int cc = (hs.opcode == 0x0F) ? (hs.opcode2 & 0x0F)
                                                   : (hs.opcode & 0x0F);
                const uint64_t dest = (uint64_t)(srcP + len) +
                    (hs.opcode == 0x0F ? (uint64_t)(int64_t)(int32_t)hs.imm.imm32
                                       : (uint64_t)(int64_t)(int8_t)hs.imm.imm8);
                copyLen = EmitJccAbs(absBuf, dest, cc);
                srcP = absBuf;
            }

            memcpy(tramp + newPos, srcP, copyLen);
            oldPos += len;
            newPos += copyLen;
        }

        EmitJmpAbs(tramp + newPos, (uint64_t)(t + oldPos));
        return oldPos;
    }

    // ==================================================================
    // 混淆形态编码（volatile 寄存器限定：rax/r8-r11；rcx/rdx 是参数、
    // non-volatile 会被原函数 epilogue 依赖，均不可用）
    // ==================================================================

    static void FillJunk(uint8_t* dst, int n)
    {
        const ULONGLONG seed = GetTickCount64() ^ ((ULONGLONG)(uintptr_t)dst << 16);
        for (int i = 0; i < n; ++i)
            dst[i] = (uint8_t)(seed >> ((i & 7) * 8));
    }

    // mov reg,imm64; jmp reg —— 仅"非参数 volatile"（rax/r10/r11）。
    // rcx/rdx/r8/r9 是 4 个参数寄存器（函数入口携带调用者值，覆盖即破坏
    // 原函数后续参数使用）；non-volatile 会被原函数 epilogue 依赖。
    //   rax: 48 B8 imm FF E0 | r10: 49 BA imm 41 FF E2 | r11: 49 BB imm 41 FF E3
    struct MovEnc { uint8_t lead[2]; uint8_t jmp[3]; int jmpLen; };
    static const MovEnc kMovTbl[3] = {
        { {0x48, 0xB8}, {0xFF, 0xE0, 0},    2 },
        { {0x49, 0xBA}, {0x41, 0xFF, 0xE2}, 3 },
        { {0x49, 0xBB}, {0x41, 0xFF, 0xE3}, 3 },
    };

    // lea reg,[rip+disp32]; jmp reg：
    //   rax: 48 8D 05 | r10: 4C 8D 15 | r11: 4C 8D 1D
    struct LeaEnc { uint8_t lead[3]; uint8_t jmp[3]; int jmpLen; };
    static const LeaEnc kLeaTbl[3] = {
        { {0x48, 0x8D, 0x05}, {0xFF, 0xE0, 0},    2 },
        { {0x4C, 0x8D, 0x15}, {0x41, 0xFF, 0xE2}, 3 },
        { {0x4C, 0x8D, 0x1D}, {0x41, 0xFF, 0xE3}, 3 },
    };

    // base = 运行时指令位置（target），lea 的 disp32 相对它计算。
    static void WritePatch(uint8_t* dst, uint8_t* base, void* handler,
                           Form form, int cover)
    {
        const uint64_t h = (uint64_t)handler;
        const ULONGLONG seed = GetTickCount64() ^ ((ULONGLONG)(uintptr_t)base << 32);
        int used = 0;

        if (form == Form::Ff25 || form == Form::Ff25Heap)
        {
            dst[0] = 0xFF; dst[1] = 0x25;
            if (cover >= 16 && (seed & 4))
            {
                dst[2] = 0x02; dst[3] = dst[4] = dst[5] = 0;   // 地址槽在 +8
                memcpy(dst + 8, &h, 8);
                FillJunk(dst + 6, 2);
                used = 16;          // 布局占满 16B（6+2+8），防尾部垃圾覆盖地址高字节
            }
            else
            {
                dst[2] = dst[3] = dst[4] = dst[5] = 0;         // 地址槽在 +6
                memcpy(dst + 6, &h, 8);
                used = 14;
            }
        }
        else if (form == Form::E9Mod)
        {
            // E9 rel32 → handler（MinHook 直跳形态）；可达性在 Create 预检。
            const int64_t delta = (int64_t)h - (int64_t)(base + 5);
            dst[0] = 0xE9;
            *(int32_t*)(dst + 1) = (int32_t)delta;
            used = 5;
        }
        else if (form == Form::MovReg)
        {
            const MovEnc& e = kMovTbl[seed % 3];
            dst[0] = e.lead[0]; dst[1] = e.lead[1];
            memcpy(dst + 2, &h, 8);
            memcpy(dst + 10, e.jmp, e.jmpLen);
            used = 10 + e.jmpLen;
        }
        else
        {
            const int64_t delta = (int64_t)h - (int64_t)(base + 7);
            if (delta >= INT32_MIN && delta <= INT32_MAX)
            {
                const LeaEnc& e = kLeaTbl[(seed >> 8) % 3];
                dst[0] = e.lead[0]; dst[1] = e.lead[1]; dst[2] = e.lead[2];
                *(int32_t*)(dst + 3) = (int32_t)delta;
                memcpy(dst + 7, e.jmp, e.jmpLen);              // jmp 在 lea 后
                used = 7 + e.jmpLen;
            }
            else
            {
                dst[0] = 0x48; dst[1] = 0xB8;                  // 超 2GB 退回 mov rax
                memcpy(dst + 2, &h, 8);
                dst[10] = 0xFF; dst[11] = 0xE0;
                used = 12;
            }
        }

        if (used < cover)
            FillJunk(dst + used, cover - used);
    }

    // ==================================================================
    // 公共接口
    // ==================================================================

    Form PickRandomForm()
    {
        // 随机池：Ff25 / MovReg / LeaReg（三形态均已实测云端放行）。
        // E9Mod 超 2GB 自动失败、Ff25Heap 为实验形态，均不入池。
        const ULONGLONG t = GetTickCount64() ^ ((ULONGLONG)(uintptr_t)&t << 32);
        return (Form)(t % 3);
    }

    bool Create(Hook* h, void* target, void* handler, Form form)
    {
        if (!h || !target || !handler) return false;

        uint8_t* t = (uint8_t*)target;

        // E9Mod 需要 ±2GB 内直跳（cover=6 无 fallback 空间）；不可达 fail-open。
        if (form == Form::E9Mod)
        {
            const int64_t d = (int64_t)handler - (int64_t)(t + 5);
            if (d < INT32_MIN || d > INT32_MAX)
                return false;
        }

        const int need = NeedCover(form);
        const SIZE_T tSize = kMaxCover * 4 + 64;
        uint8_t* tramp = (uint8_t*)VirtualAlloc(nullptr, tSize,
                                                MEM_COMMIT | MEM_RESERVE,
                                                PAGE_EXECUTE_READWRITE);
        if (!tramp) return false;

        // Ff25Heap：堆区跳板（FF 25 + abs64 → 真 handler），函数头目标指向它。
        uint8_t* heapStub = nullptr;
        if (form == Form::Ff25Heap)
        {
            heapStub = (uint8_t*)VirtualAlloc(nullptr, 16,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE);
            if (!heapStub)
            {
                VirtualFree(tramp, 0, MEM_RELEASE);
                return false;
            }
            heapStub[0] = 0xFF; heapStub[1] = 0x25;
            heapStub[2] = heapStub[3] = heapStub[4] = heapStub[5] = 0;
            memcpy(heapStub + 6, &handler, 8);          // jmp [rip+0] → handler
            DWORD op = 0;
            VirtualProtect(heapStub, 16, PAGE_EXECUTE_READ, &op);
            handler = heapStub;                          // 写入目标 = 堆区
        }

        const int cover = BuildTrampoline(t, tramp, need);
        if (cover < need)
        {
            if (heapStub) VirtualFree(heapStub, 0, MEM_RELEASE);
            VirtualFree(tramp, 0, MEM_RELEASE);
            return false;
        }

        DWORD oldProt = 0;
        VirtualProtect(tramp, tSize, PAGE_EXECUTE_READ, &oldProt);

        const int frozen = FreezeThreads(true);
        if (frozen == 0)
        {
            FreezeThreads(false);
            if (heapStub) VirtualFree(heapStub, 0, MEM_RELEASE);
            VirtualFree(tramp, 0, MEM_RELEASE);
            return false;
        }

        DWORD protOld = 0;
        if (!VirtualProtect(t, cover, PAGE_EXECUTE_READWRITE, &protOld))
        {
            FreezeThreads(false);
            if (heapStub) VirtualFree(heapStub, 0, MEM_RELEASE);
            VirtualFree(tramp, 0, MEM_RELEASE);
            return false;
        }

        uint8_t patch[64] = {};
        WritePatch(patch, t, handler, form, cover);
        memcpy(h->backup, t, cover);
        memcpy(t, patch, cover);
        FlushInstructionCache(GetCurrentProcess(), t, cover);

        VirtualProtect(t, cover, protOld, &protOld);
        FreezeThreads(false);

        h->target = t;
        h->cover  = cover;
        h->form   = form;
        h->tramp  = tramp;
        h->aux    = heapStub;
        return true;
    }

    void Remove(Hook* h)
    {
        if (!h || !h->target || h->cover <= 0) return;

        FreezeThreads(true);
        DWORD protOld = 0;
        if (VirtualProtect(h->target, h->cover, PAGE_EXECUTE_READWRITE, &protOld))
        {
            memcpy(h->target, h->backup, h->cover);
            FlushInstructionCache(GetCurrentProcess(), h->target, h->cover);
            VirtualProtect(h->target, h->cover, protOld, &protOld);
        }
        FreezeThreads(false);

        if (h->tramp)
            VirtualFree(h->tramp, 0, MEM_RELEASE);
        if (h->aux)
            VirtualFree(h->aux, 0, MEM_RELEASE);

        h->target = nullptr;
        h->cover  = 0;
        h->tramp  = nullptr;
        h->aux    = nullptr;
    }
}
