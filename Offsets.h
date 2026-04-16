#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <cstring>
#include "sdk.h"

// =============================================================
//  Offsets.h  —  UE5.3 AOB Pattern Scanner & Offset Table
//  Fox build  |  Valorant UE5.3 compat
//  All offsets resolved at runtime via AOB scan + RIP resolve.
//  Rescan after every Valorant patch — binary shifts frequently.
// =============================================================

// ─────────────────────────────────────────────────────────────
//  RESOLVED OFFSET TABLE
//  Populated by Offsets::Init() at runtime.
//  Access via Offsets::g (e.g. Offsets::g.GWorld)
// ─────────────────────────────────────────────────────────────
struct OffsetTable
{
    // ── Globals ───────────────────────────────────────────────
    uintptr_t GNamePoolData;   // FNamePool instance base
    uintptr_t GUObjectArray;   // FUObjectArray base (plaintext)
    uintptr_t GWorld;          // *UWorld pointer (plaintext)

    // ── UObject ───────────────────────────────────────────────
    uintptr_t UObject_NamePrivate;   // = 0x18  (UE5.3 fixed)
    uintptr_t UObject_Outer;         // = 0x20
    uintptr_t UObject_InternalIndex; // = 0x0C

    // ── AActor ────────────────────────────────────────────────
    uintptr_t AActor_RootComponent;  // ~0x190  rescan
    uintptr_t AActor_bHidden;        // ~0x100  rescan

    // ── USceneComponent ───────────────────────────────────────
    uintptr_t USceneComponent_RelativeLocation; // ~0x11C rescan
    uintptr_t USceneComponent_ComponentVelocity;// ~0x130 rescan

    // ── USkeletalMeshComponent ────────────────────────────────
    uintptr_t USkeletalMesh_BoneSpaceTransforms; // = 0x5E0 (UE5.3)

    // ── APlayerState ──────────────────────────────────────────
    uintptr_t APlayerState_PlayerName;  // ~0x3A0 rescan
    uintptr_t APlayerState_Score;       // ~0x2C8 rescan

    // ── APlayerController ─────────────────────────────────────
    uintptr_t APlayerController_AcknowledgedPawn; // ~0x350 rescan

    // ── UWorld ────────────────────────────────────────────────
    uintptr_t UWorld_PersistentLevel;   // ~0x58  rescan
    uintptr_t UWorld_OwningGameInstance;// ~0x1B8 rescan
    uintptr_t UWorld_GameState;         // ~0xB8  rescan

    // ── ULevel ────────────────────────────────────────────────
    uintptr_t ULevel_AActors;           // ~0x98  rescan

    // ── UGameInstance ─────────────────────────────────────────
    uintptr_t UGameInstance_LocalPlayers; // ~0x38 rescan

    // ── ULocalPlayer ──────────────────────────────────────────
    uintptr_t ULocalPlayer_PlayerController; // ~0x30 rescan

    // ── Camera ────────────────────────────────────────────────
    uintptr_t CameraManager_CameraCache;     // ~0x1A50 rescan
    // CameraCache -> FCameraCacheEntry -> FMinimalViewInfo
    // FMinimalViewInfo: Location+0x0, Rotation+0xC, FOV+0x18

    // ── Damage / Health (Valorant-specific, rescan every patch) ─
    uintptr_t ValCharacter_HealthComponent; // rescan
    uintptr_t HealthComponent_CurrentHP;    // rescan
    uintptr_t HealthComponent_MaxHP;        // rescan
};

// ─────────────────────────────────────────────────────────────
//  AOB PATTERN DEFINITIONS
//  Format: { pattern bytes, mask, rip_offset, instr_size, description }
//  rip_offset  = byte offset of the 4-byte disp32 inside the instruction
//  instr_size  = total instruction length (for RIP calc)
//  is_direct   = true  → resolved addr IS the value (no extra deref)
//              = false → resolved addr is a pointer, dereference once
// ─────────────────────────────────────────────────────────────
struct AobEntry
{
    const char* pattern;
    const char* mask;
    uint32_t    rip_offset;
    uint32_t    instr_size;
    bool        is_direct;   // false = dereference the resolved RIP addr
    const char* desc;
};

// NOTE: These patterns target VALORANT-Win64-Shipping.exe UE5.3 build.
// Verify in x64dbg / IDA after each patch. Wildcards = \x00 with mask '?'.
static const AobEntry AOB_GNamePoolData =
{
    "\x48\x8D\x05\x00\x00\x00\x00"   // LEA RAX, [RIP+disp32]  ; GNamePoolData
    "\xEB\x00"                         // JMP short
    "\x48\x8D\x0D\x00\x00\x00\x00",  // LEA RCX, [RIP+disp32]
    "xxx????x?xxx????",
    3, 7, true,
    "GNamePoolData — FNamePool instance"
};

static const AobEntry AOB_GUObjectArray =
{
    "\x48\x8B\x05\x00\x00\x00\x00"   // MOV RAX, [RIP+disp32]  ; GUObjectArray
    "\x48\x85\xC0"                    // TEST RAX, RAX
    "\x74\x00"                        // JZ short
    "\x48\x8B\x40\x00",              // MOV RAX, [RAX+xx]
    "xxx????xxx x?xxx?",
    3, 7, true,
    "GUObjectArray — FUObjectArray base (plaintext UE5.3)"
};

static const AobEntry AOB_GWorld =
{
    "\x48\x8B\x1D\x00\x00\x00\x00"  // MOV RBX, [RIP+disp32]  ; GWorld
    "\x48\x85\xDB"                   // TEST RBX, RBX
    "\x74\x00",                      // JZ short
    "xxx????xxx?",
    3, 7, false,                     // dereference → *UWorld
    "GWorld — UWorld pointer (plaintext UE5.3)"
};

// ─────────────────────────────────────────────────────────────
//  STATIC OFFSETS  (UE5.3 — confirmed, do not rescan unless
//  Unreal Engine version changes)
// ─────────────────────────────────────────────────────────────
namespace StaticOffsets
{
    // UObject
    constexpr uintptr_t UObject_ObjectFlags    = 0x08;
    constexpr uintptr_t UObject_InternalIndex  = 0x0C;
    constexpr uintptr_t UObject_NamePrivate    = 0x18; // UE5: was 0x10 in UE4
    constexpr uintptr_t UObject_Outer          = 0x20;

    // FTransform size
    constexpr uintptr_t FTransform_Size        = 0x30;

    // USkeletalMeshComponent
    constexpr uintptr_t BoneSpaceTransforms    = 0x5E0; // UE5.3 confirmed

    // FUObjectItem stride
    constexpr uintptr_t FUObjectItem_Size      = 0x20;

    // FChunkedFixedUObjectArray chunk size
    constexpr int32_t   ObjectChunkSize        = 65536;
}

// ─────────────────────────────────────────────────────────────
//  DYNAMIC OFFSETS  (rescan every patch)
//  Values below are last-known-good for build ~9.x
//  Mark with RESCAN comment when uncertain.
// ─────────────────────────────────────────────────────────────
namespace DynamicOffsets
{
    // AActor
    constexpr uintptr_t AActor_RootComponent         = 0x190; // RESCAN
    constexpr uintptr_t AActor_bHidden               = 0x100; // RESCAN
    constexpr uintptr_t AActor_bCanBeDamaged         = 0x108; // RESCAN

    // USceneComponent
    constexpr uintptr_t SceneComp_RelativeLocation   = 0x11C; // RESCAN
    constexpr uintptr_t SceneComp_ComponentVelocity  = 0x130; // RESCAN

    // APlayerState
    constexpr uintptr_t PlayerState_PlayerName       = 0x3A0; // RESCAN
    constexpr uintptr_t PlayerState_Score            = 0x2C8; // RESCAN
    constexpr uintptr_t PlayerState_PlayerId         = 0x2D4; // RESCAN

    // APlayerController
    constexpr uintptr_t PlayerController_AcknPawn    = 0x350; // RESCAN
    constexpr uintptr_t PlayerController_PlayerState = 0x240; // RESCAN
    constexpr uintptr_t PlayerController_CamManager  = 0x348; // RESCAN

    // UWorld
    constexpr uintptr_t World_PersistentLevel        = 0x58;  // RESCAN
    constexpr uintptr_t World_OwningGameInstance     = 0x1B8; // RESCAN
    constexpr uintptr_t World_GameState              = 0xB8;  // RESCAN
    constexpr uintptr_t World_NetDriver              = 0xE8;  // RESCAN

    // ULevel
    constexpr uintptr_t Level_AActors                = 0x98;  // RESCAN

    // UGameInstance
    constexpr uintptr_t GameInstance_LocalPlayers    = 0x38;  // RESCAN

    // ULocalPlayer
    constexpr uintptr_t LocalPlayer_PlayerController = 0x30;  // RESCAN

    // APlayerCameraManager — CameraCache
    constexpr uintptr_t CamManager_CameraCache       = 0x1A50; // RESCAN
    // FMinimalViewInfo inside FCameraCacheEntry
    constexpr uintptr_t ViewInfo_Location            = 0x10;
    constexpr uintptr_t ViewInfo_Rotation            = 0x1C;
    constexpr uintptr_t ViewInfo_FOV                 = 0x28;

    // Valorant-specific: HealthComponent (rescan every patch)
    constexpr uintptr_t ValChar_HealthComp           = 0x000; // RESCAN — unknown
    constexpr uintptr_t HealthComp_CurrentHP         = 0x000; // RESCAN — unknown
    constexpr uintptr_t HealthComp_MaxHP             = 0x000; // RESCAN — unknown
}

// ─────────────────────────────────────────────────────────────
//  Offsets namespace — runtime init + global table
// ─────────────────────────────────────────────────────────────
namespace Offsets
{
    inline OffsetTable g{}; // global resolved table

    // Internal: scan + resolve one AOB entry
    static uintptr_t ResolveAob(uintptr_t start, size_t size,
        const AobEntry& e)
    {
        uintptr_t hit = PatternScan(start, size, e.pattern, e.mask);
        if (!hit) return 0;

        uintptr_t resolved = ResolveRIP(hit, e.rip_offset, e.instr_size);

        if (!e.is_direct)
            resolved = RPM<uintptr_t>(resolved); // single deref for ptr-to-ptr

        return resolved;
    }

    // Call once from DllMain / init thread.
    // module = base address of VALORANT-Win64-Shipping.exe
    inline bool Init(uintptr_t module = 0)
    {
        if (!module)
            module = reinterpret_cast<uintptr_t>(
                GetModuleHandleA("VALORANT-Win64-Shipping.exe"));
        if (!module) return false;

        MODULEINFO mi{};
        GetModuleInformation(GetCurrentProcess(),
            reinterpret_cast<HMODULE>(module), &mi, sizeof(mi));
        const size_t sz = mi.SizeOfImage;

        // ── Scan globals ──────────────────────────────────────
        g.GNamePoolData = ResolveAob(module, sz, AOB_GNamePoolData);
        g.GUObjectArray = ResolveAob(module, sz, AOB_GUObjectArray);
        g.GWorld        = ResolveAob(module, sz, AOB_GWorld);

        if (!g.GNamePoolData || !g.GUObjectArray || !g.GWorld)
            return false; // critical — bail out

        // ── Static offsets (UE5.3 fixed) ─────────────────────
        g.UObject_NamePrivate    = StaticOffsets::UObject_NamePrivate;
        g.UObject_Outer          = StaticOffsets::UObject_Outer;
        g.UObject_InternalIndex  = StaticOffsets::UObject_InternalIndex;
        g.USkeletalMesh_BoneSpaceTransforms = StaticOffsets::BoneSpaceTransforms;

        // ── Dynamic offsets (last-known-good, rescan on patch) ─
        g.AActor_RootComponent          = DynamicOffsets::AActor_RootComponent;
        g.AActor_bHidden                = DynamicOffsets::AActor_bHidden;
        g.USceneComponent_RelativeLocation  = DynamicOffsets::SceneComp_RelativeLocation;
        g.USceneComponent_ComponentVelocity = DynamicOffsets::SceneComp_ComponentVelocity;
        g.APlayerState_PlayerName       = DynamicOffsets::PlayerState_PlayerName;
        g.APlayerState_Score            = DynamicOffsets::PlayerState_Score;
        g.APlayerController_AcknowledgedPawn = DynamicOffsets::PlayerController_AcknPawn;
        g.UWorld_PersistentLevel        = DynamicOffsets::World_PersistentLevel;
        g.UWorld_OwningGameInstance     = DynamicOffsets::World_OwningGameInstance;
        g.UWorld_GameState              = DynamicOffsets::World_GameState;
        g.ULevel_AActors                = DynamicOffsets::Level_AActors;
        g.UGameInstance_LocalPlayers    = DynamicOffsets::GameInstance_LocalPlayers;
        g.ULocalPlayer_PlayerController = DynamicOffsets::LocalPlayer_PlayerController;
        g.CameraManager_CameraCache     = DynamicOffsets::CamManager_CameraCache;
        g.ValCharacter_HealthComponent  = DynamicOffsets::ValChar_HealthComp;
        g.HealthComponent_CurrentHP     = DynamicOffsets::HealthComp_CurrentHP;
        g.HealthComponent_MaxHP         = DynamicOffsets::HealthComp_MaxHP;

        // ── Wire into SDK ─────────────────────────────────────
        SDK::Init(g.GNamePoolData, g.GUObjectArray, g.GWorld);

        return true;
    }

    // Dump resolved table to debug output (call after Init)
    inline void DumpToDebug()
    {
        char buf[256];
#define DUMP(x) \
    wsprintfA(buf, "[Offsets] " #x " = 0x%llX\n", (unsigned long long)g.x); \
    OutputDebugStringA(buf);

        DUMP(GNamePoolData)
        DUMP(GUObjectArray)
        DUMP(GWorld)
        DUMP(UObject_NamePrivate)
        DUMP(UObject_Outer)
        DUMP(USkeletalMesh_BoneSpaceTransforms)
        DUMP(AActor_RootComponent)
        DUMP(APlayerController_AcknowledgedPawn)
        DUMP(UWorld_PersistentLevel)
        DUMP(CameraManager_CameraCache)
#undef DUMP
    }
} // namespace Offsets
