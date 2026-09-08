#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "PickupFilter.h"
#include "InteeBtn.h"
#include "Lists.h"
#include "Patterns.h"
#include "Config.h"
#include "Logger.h"
#include <atomic>
#include <cstdint>
#include <cstring>

// ============================================================================
// PickupFilter —— 拾取条目过滤（NOEFNCCMEBC，dump: NCLIFAHNANC.NOEFNCCMEBC，
// RVA 0xF4944B0）。
//
//   Intee 面板组件中 type=1 按钮的执行分支：AddPickupOption 建条目并渲染。
//   黑名单命中无条件拦截；白名单命中放行；否则按默认规则——命中目标
//   图标族（UI_ItemIcon_112 子串）才拦，提示框不再弹出。
//   读到的字段：+0x18 物品名；图标走接口方法 #2（InteeBtn 统一查表）。
//
//   hook 机制：ObfHook（src/ObfHook）——通用 hde64 切分 + 跳转绝对化 +
//   混淆形态写入（Ff25/MovReg/LeaReg 随机），不依赖固定 prologue。
//   切回标准 MinHook：git 历史基线（6256a28）即 MinHook 版。
// ============================================================================

#include "ObfHook.h"

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

// 按字节数补空格到固定列宽。仅用于纯 ASCII 字段区：字节宽 = 显示列宽，
// 不受查看字体里中文字符宽度的影响（中文字段一律放行尾）。
static void PadBytes(char* buf, int bufChars, int* used, int width)
{
    while (*used < width && *used < bufChars - 1)
        buf[(*used)++] = ' ';
}

static __int64 __fastcall PD_Handler(__int64 a1, __int64 a2)
{
    // 热路径只做内存操作；文件 IO 全部归 watcher 线程。

    if (!a2)
        return g_orig(a1, a2);

    const bool filter  = Config::g_pickupFilterEnabled.load(std::memory_order_acquire);
    const bool logging = Logger::g_logWriteEnabled.load(std::memory_order_acquire);

    // 两个开关全关时直接放行——每个拾取都会经过这里，早退是最大收益。
    if (!filter && !logging)
        return g_orig(a1, a2);

    char iconUtf8[64] = {};
    char nameUtf8[128] = {};
    bool shouldBlock = false;

    __try {
        // 图标统一走接口方法 #2（查表，含 NPC 对话的配置回退）。
        InteeBtn::ReadStringUtf8((void*)a2, 2, iconUtf8, 64);

        const bool isTargetIcon =
            iconUtf8[0] && strstr(iconUtf8, "UI_ItemIcon_112") != nullptr;

        // 名单判定与日志都可能需要 name；仅日志关闭且过滤关闭时可省去转换。
        if (logging || filter)
            InteeBtn::ReadIl2CppUtf8(*(__int64*)(a2 + 0x18), nameUtf8, 128);

        if (filter) {
            // 名单判定：黑名单 > 白名单 > 默认（命中目标图标族才拦）。
            Lists::Verdict v = Lists::Evaluate(nameUtf8, iconUtf8);
            if (v == Lists::Verdict::Block)
                shouldBlock = true;
            else if (v == Lists::Verdict::Allow)
                shouldBlock = false;
            else
                shouldBlock = isTargetIcon;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // 热路径异常保持静默。
    }

    // 每个拾取都输出一行；被拦的行尾带 BLOCK 标记（PASS 词省略）。
    if (logging)
    {
        char line[320] = {};
        int used = 0;
        AppendField(line, sizeof(line), &used, "icon", iconUtf8);
        PadBytes(line, sizeof(line), &used, 34);
        AppendRaw(line, sizeof(line), &used, " ");
        AppendField(line, sizeof(line), &used, "text", nameUtf8);
        if (shouldBlock)
            AppendRaw(line, sizeof(line), &used, " BLOCK");
        LOG("拾取类", "%s", line);
    }

    if (shouldBlock)
        return 0;

    return g_orig(a1, a2);
}

static bool DoInit()
{
    if (!g_base)
        g_base = (uint8_t*)GetModuleHandleW(nullptr);
    if (!g_base) return false;

    g_target = g_base + Offsets::RVA::PickupDataAdd;

    if (!ObfHook::Create(&g_hook, g_target, (void*)&PD_Handler,
                         ObfHook::PickRandomForm())) {
        LOG("拾取类", "ObfHook::Create failed at %llX (prologue mismatch?)",
            (uint64_t)g_target);
        return false;
    }

    g_orig = (tOriginal2)g_hook.tramp;
    g_hooked.store(true, std::memory_order_release);
    LOG("拾取类", "target=%llX (ObfHook form=%d cover=%d)",
        (uint64_t)g_target, (int)g_hook.form, g_hook.cover);
    return true;
}

bool PickupFilter::Init()
{
    __try { return DoInit(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_MSG("拾取类", "Init EXCEPTION!");
        return false;
    }
}

void PickupFilter::Uninit()
{
    if (!g_hooked.exchange(false))
        return;

    ObfHook::Remove(&g_hook);
    g_orig = nullptr;
    LOG_MSG("拾取类", "Uninit OK (ObfHook)");
}
