#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "InteeProbe.h"
#include "InteeBtn.h"
#include "Lists.h"
#include "Patterns.h"
#include "Config.h"
#include "Logger.h"
#include "ObfHook.h"
#include <atomic>
#include <cstdint>
#include <cstring>


static uint8_t* g_base = nullptr;
static void*    g_target = nullptr;
static std::atomic<bool> g_hooked{ false };
static ObfHook::Hook g_hook;

typedef __int64 (__fastcall* tOriginal2)(__int64, __int64);
static tOriginal2 g_orig = nullptr;


// 追加 key='value'（无尾随空格）。
static void AppendField(char* buf, int bufChars, int* used,
                        const char* key, const char* value)
{
    int n = sprintf_s(buf + *used, (size_t)(bufChars - *used), "%s='%s'", key, value);
    if (n > 0) *used += n;
}

static void AppendRaw(char* buf, int bufChars, int* used, const char* text)
{
    int n = sprintf_s(buf + *used, (size_t)(bufChars - *used), "%s", text);
    if (n > 0) *used += n;
}

static void PadBytes(char* buf, int bufChars, int* used, int width)
{
    while (*used < width && *used < bufChars - 1)
        buf[(*used)++] = ' ';
}

// 固定字段读取 + 黑名单判定。返回是否命中黑名单（供上层跳过原函数）。
// 拦截判定与 [Log] 解耦：判定始终执行（仍受 [Blacklist] 开关控制），
// 日志行仅在 [Log] 开启时构建输出——与拾取路径"拦截跟随开关、日志跟随 [Log]"
// 的语义保持一致。
static bool EvalBtnFields(__int64 a2, bool logging)
{
    char nameUtf8[96] = {};
    char dispUtf8[96] = {};
    char iconUtf8[96] = {};

    __try {
        // 文本走字段（变体布局：+0x18 物品名 / +0x20 交互文本）。
        InteeBtn::ReadIl2CppUtf8(*(__int64*)(a2 + 0x18), nameUtf8, 96);
        InteeBtn::ReadIl2CppUtf8(*(__int64*)(a2 + 0x20), dispUtf8, 96);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;   // 读失败不拦截，放行
    }

    // 图标统一走接口方法 #2（查表，含 NPC 对话的配置回退）。
    InteeBtn::ReadStringUtf8((void*)a2, 2, iconUtf8, 96);

    const bool block = Lists::IsBlacklisted(
        nameUtf8[0] ? nameUtf8 : dispUtf8, iconUtf8);

    if (logging)
    {
        char line[512] = {};
        int used = 0;
        AppendField(line, sizeof(line), &used, "icon", iconUtf8);
        PadBytes(line, sizeof(line), &used, 34);
        AppendRaw(line, sizeof(line), &used, " ");
        if (nameUtf8[0] && dispUtf8[0]) {
            AppendField(line, sizeof(line), &used, "name", nameUtf8);
            AppendRaw(line, sizeof(line), &used, " ");
            AppendField(line, sizeof(line), &used, "disp", dispUtf8);
        } else {
            AppendField(line, sizeof(line), &used, "text",
                        nameUtf8[0] ? nameUtf8 : dispUtf8);
        }
        if (block)
            AppendRaw(line, sizeof(line), &used, " BLOCK");

        LOG("交互类", "%s", line);
    }

    return block;
}

static __int64 __fastcall ProbeHandler(__int64 a1, __int64 a2)
{
    if (a2)
    {
        const bool logging =
            Logger::g_logWriteEnabled.load(std::memory_order_acquire);
        if (EvalBtnFields(a2, logging))
            return 0;
    }
    return g_orig(a1, a2);
}

static bool DoInit()
{
    if (!g_base)
        g_base = (uint8_t*)GetModuleHandleW(nullptr);
    if (!g_base) return false;

    g_target = g_base + Offsets::RVA::BtnDispatch;

    if (!ObfHook::Create(&g_hook, g_target, (void*)&ProbeHandler,
                         ObfHook::PickRandomForm())) {
        LOG("交互类", "ObfHook::Create failed at %llX (prologue mismatch?)",
            (uint64_t)g_target);
        return false;
    }

    g_orig = (tOriginal2)g_hook.tramp;
    g_hooked.store(true, std::memory_order_release);
    LOG("交互类", "target=%llX (ObfHook form=%d cover=%d aux=%p)",
        (uint64_t)g_target, (int)g_hook.form, g_hook.cover, g_hook.aux);
    return true;
}

bool InteeProbe::Init()
{
    __try { return DoInit(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_MSG("交互类", "Init EXCEPTION!");
        return false;
    }
}

void InteeProbe::Uninit()
{
    if (!g_hooked.exchange(false))
        return;

    ObfHook::Remove(&g_hook);
    g_orig = nullptr;
    LOG_MSG("交互类", "Uninit OK (ObfHook)");
}
