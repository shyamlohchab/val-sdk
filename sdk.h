#pragma once
#include <Windows.h>
#include <cstdint>
#include <string>
#include <array>

// =============================================================
//  sdk.h  —  UE5.3 FNamePool Reader
//  Fox build  |  Valorant UE5.3 compat
//  GUObjectArray / GWorld: plaintext (no decrypt chain)
//  BoneSpaceTransforms replaces ComponentSpaceBases @ 0x5E0
// =============================================================

// ─────────────────────────────────────────────────────────────
//  MEMORY HELPERS
// ─────────────────────────────────────────────────────────────
template<typename T>
static inline T RPM(uintptr_t addr)
{
    T val{};
    ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr),
        &val, sizeof(T), nullptr);
    return val;
}

static inline std::string RPM_STR(uintptr_t addr, size_t maxLen = 256)
{
    char buf[256] = {};
    ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(addr),
        buf, min(maxLen, sizeof(buf) - 1), nullptr);
    return std::string(buf);
}

// ─────────────────────────────────────────────────────────────
//  UE5.3 FNamePool CONSTANTS
// ─────────────────────────────────────────────────────────────
// GNamePoolData is the global FNamePool instance.
// Layout (UE5.3, x64):
//   +0x00  Lock              (FRWLock, 8 bytes)
//   +0x08  CurrentBlock      (uint32_t)
//   +0x0C  CurrentByteCursor (uint32_t)
//   +0x10  Blocks[2048]      (FNameEntryAllocator::BlockType*)
//
// Each block is a 64 KB slab of FNameEntry records.
// FNameEntry layout:
//   +0x00  Header (uint16_t)
//          bits[0]    = bIsWide
//          bits[1..5] = len (narrow) or len (wide)
//          bits[6..15]= unused / padding
//   +0x02  AnsiName[len]  (char, narrow) OR
//          WideName[len]  (wchar_t, wide)
//
// FName ComparisonIndex (uint32_t):
//   bits[0..15]  = block offset  (byte offset inside block >> 2)
//   bits[16..31] = block index
//
// So:
//   blockIdx  = index >> 16
//   offset    = (index & 0xFFFF) << 2   (stride = 4 bytes)

constexpr uint32_t FNAME_BLOCK_OFFSET_BITS = 16;
constexpr uint32_t FNAME_BLOCK_OFFSET_MASK = 0xFFFF;
constexpr uint32_t FNAME_ENTRY_STRIDE      = 4;       // each slot is 4-byte aligned
constexpr uint32_t FNAME_MAX_BLOCK_BITS    = 13;      // 2^13 = 8192 blocks max
constexpr size_t   FNAME_BLOCK_SIZE        = 0x10000; // 64 KB per block

// ─────────────────────────────────────────────────────────────
//  FNameEntry header decode
// ─────────────────────────────────────────────────────────────
struct FNameEntryHeader
{
    uint16_t raw;

    // UE5.3: bit0 = bIsWide, bits 6..15 = len
    bool     IsWide()  const { return (raw & 0x1) != 0; }
    uint32_t Len()     const { return (raw >> 6) & 0x3FF; }  // 10 bits for length
};

// ─────────────────────────────────────────────────────────────
//  FNamePool reader
// ─────────────────────────────────────────────────────────────
class FNamePool
{
public:
    // Call once after finding GNamePoolData via AOB scan.
    // base = address of the global FNamePool instance.
    static void Init(uintptr_t base)
    {
        s_base = base;
    }

    // Resolve FName ComparisonIndex -> UTF-8 string.
    // Returns "<invalid>" on any failure.
    static std::string GetName(uint32_t comparisonIndex)
    {
        if (!s_base || comparisonIndex == 0)
            return "<none>";

        const uint32_t blockIdx = comparisonIndex >> FNAME_BLOCK_OFFSET_BITS;
        const uint32_t byteOff  = (comparisonIndex & FNAME_BLOCK_OFFSET_MASK)
                                  << 2; // x4 stride

        // Blocks[] starts at base+0x10
        // Each element is a pointer (8 bytes on x64)
        const uintptr_t blocksBase = s_base + 0x10;
        const uintptr_t blockPtr   = RPM<uintptr_t>(blocksBase + blockIdx * 8);

        if (!blockPtr)
            return "<invalid>";

        const uintptr_t entryAddr = blockPtr + byteOff;

        // Read the 2-byte header
        FNameEntryHeader hdr;
        hdr.raw = RPM<uint16_t>(entryAddr);

        const uint32_t len = hdr.Len();
        if (len == 0 || len > 1024)
            return "<invalid>";

        // Name data starts right after the 2-byte header
        const uintptr_t nameAddr = entryAddr + sizeof(uint16_t);

        if (hdr.IsWide())
        {
            // Wide (UTF-16) path — rare in Valorant but handle it
            wchar_t wbuf[1024] = {};
            ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<LPCVOID>(nameAddr),
                wbuf, len * sizeof(wchar_t), nullptr);
            wbuf[len] = L'\0';

            // Convert to UTF-8 via WideCharToMultiByte
            char mbuf[2048] = {};
            WideCharToMultiByte(CP_UTF8, 0, wbuf, len, mbuf, sizeof(mbuf)-1, nullptr, nullptr);
            return std::string(mbuf);
        }
        else
        {
            // Narrow (ANSI/UTF-8) path — normal case
            char buf[1024] = {};
            ReadProcessMemory(GetCurrentProcess(),
                reinterpret_cast<LPCVOID>(nameAddr),
                buf, len, nullptr);
            buf[len] = '\0';
            return std::string(buf);
        }
    }

private:
    static inline uintptr_t s_base = 0;
};

// ─────────────────────────────────────────────────────────────
//  FName  (UE5.3)
//  Size: 8 bytes
// ─────────────────────────────────────────────────────────────
struct FName
{
    uint32_t ComparisonIndex;  // +0x00  chunk/offset packed index
    uint32_t Number;           // +0x04  numeric suffix (0 = none)

    std::string ToString() const
    {
        std::string s = FNamePool::GetName(ComparisonIndex);
        if (Number > 0)
            s += '_' + std::to_string(Number - 1);
        return s;
    }
};
static_assert(sizeof(FName) == 0x8, "FName size mismatch");

// ─────────────────────────────────────────────────────────────
//  UObject  (UE5.3)
//  Offsets from ReClass / UE5.3 source
// ─────────────────────────────────────────────────────────────
struct UObject
{
    uint8_t  pad_0000[0x08]; // vtable
    int32_t  ObjectFlags;    // +0x08
    int32_t  InternalIndex;  // +0x0C  GUObjectArray index
    // UE5 moved NamePrivate to +0x18 (was +0x10 in UE4)
    uint8_t  pad_0010[0x08];
    FName    NamePrivate;    // +0x18
    UObject* Outer;          // +0x20

    std::string GetName() const
    {
        return RPM<FName>(reinterpret_cast<uintptr_t>(this) + 0x18).ToString();
    }

    std::string GetFullName() const;
};

// ─────────────────────────────────────────────────────────────
//  UField / UStruct / UClass  (minimal, for traversal)
// ─────────────────────────────────────────────────────────────
struct UField : UObject
{
    UField* Next; // +0x28
};

struct UStruct : UField
{
    uint8_t  pad_UStruct[0x10];
    UField*  Children;          // +0x40
    void*    LinkedProperties;  // +0x48  UE5: replaces Children for props
    int32_t  PropertiesSize;    // +0x50
    int32_t  MinAlignment;      // +0x54
};

struct UClass : UStruct
{
    uint8_t pad_UClass[0x28];
    UObject* ClassDefaultObject; // +0x80 (approx, rescan if needed)
};

// ─────────────────────────────────────────────────────────────
//  FTransform  (UE5.3 — 48 bytes, SSE-aligned)
// ─────────────────────────────────────────────────────────────
struct FQuat  { float X, Y, Z, W; };
struct FVector{ float X, Y, Z;    };

struct FTransform
{
    FQuat   Rotation;    // +0x00  16 bytes
    FVector Translation; // +0x10  12 bytes
    float   pad_1C;      // +0x1C  alignment
    FVector Scale3D;     // +0x20  12 bytes
    float   pad_2C;      // +0x2C
};
static_assert(sizeof(FTransform) == 0x30, "FTransform size mismatch");

// ─────────────────────────────────────────────────────────────
//  USkeletalMeshComponent — BoneSpaceTransforms (UE5.3)
//  Was: ComponentSpaceBases @ old offset
//  Now: BoneSpaceTransforms @ 0x5E0 (rescan if binary updates)
// ─────────────────────────────────────────────────────────────
struct TArray_FTransform
{
    FTransform* Data;  // +0x00
    int32_t     Count; // +0x08
    int32_t     Max;   // +0x0C
};

struct USkeletalMeshComponent
{
    uint8_t            pad[0x5E0];
    TArray_FTransform  BoneSpaceTransforms; // +0x5E0  (UE5.3)
};

// ─────────────────────────────────────────────────────────────
//  GUObjectArray  (UE5.3 — plaintext, no decryption)
// ─────────────────────────────────────────────────────────────
struct FUObjectItem
{
    UObject* Object;       // +0x00
    int32_t  Flags;        // +0x08
    int32_t  ClusterIndex; // +0x0C
    int32_t  SerialNumber; // +0x10
    uint8_t  pad[0x0C];    // +0x14  padding to 0x20
};
static_assert(sizeof(FUObjectItem) == 0x20, "FUObjectItem size mismatch");

struct FChunkedFixedUObjectArray
{
    FUObjectItem** Objects;        // +0x00  pointer to chunk table
    FUObjectItem*  PreAllocated;   // +0x08
    int32_t        MaxElements;    // +0x10
    int32_t        NumElements;    // +0x14
    int32_t        MaxChunks;      // +0x18
    int32_t        NumChunks;      // +0x1C
};

struct FUObjectArray
{
    int32_t                  ObjFirstGCIndex;      // +0x00
    int32_t                  ObjLastNonGCIndex;    // +0x04
    int32_t                  MaxObjectsNotConsideredByGC; // +0x08
    bool                     OpenForDisregardForGC;       // +0x0C
    uint8_t                  pad_0D[0x03];
    FChunkedFixedUObjectArray ObjObjects;          // +0x10
};

// ─────────────────────────────────────────────────────────────
//  UWorld  (UE5.3 — plaintext pointer)
// ─────────────────────────────────────────────────────────────
struct UWorld : UObject
{
    uint8_t  pad_UWorld[0x30];
    void*    PersistentLevel;  // +0x58 (approx, rescan as needed)
};

// ─────────────────────────────────────────────────────────────
//  SDK globals — set once from AOB scan results
// ─────────────────────────────────────────────────────────────
namespace SDK
{
    inline uintptr_t      GNamePoolBase  = 0;
    inline FUObjectArray* GUObjectArray  = nullptr;
    inline uintptr_t      GWorldPtr      = 0;

    inline void Init(
        uintptr_t namePoolBase,
        uintptr_t uObjectArrayAddr,
        uintptr_t gWorldPtrAddr)
    {
        GNamePoolBase = namePoolBase;
        FNamePool::Init(namePoolBase);
        GUObjectArray = reinterpret_cast<FUObjectArray*>(uObjectArrayAddr);
        GWorldPtr     = gWorldPtrAddr;
    }

    inline UObject* GetObjectByIndex(int32_t index)
    {
        if (!GUObjectArray) return nullptr;
        const auto& arr = GUObjectArray->ObjObjects;
        if (index < 0 || index >= arr.NumElements) return nullptr;

        constexpr int32_t CHUNK_SIZE = 65536;
        const int32_t chunkIdx = index / CHUNK_SIZE;
        const int32_t chunkOff = index % CHUNK_SIZE;

        FUObjectItem* chunk = RPM<FUObjectItem*>(
            reinterpret_cast<uintptr_t>(arr.Objects) + chunkIdx * 8);
        if (!chunk) return nullptr;

        return RPM<UObject*>(
            reinterpret_cast<uintptr_t>(chunk) + chunkOff * sizeof(FUObjectItem));
    }

    inline UWorld* GetWorld()
    {
        if (!GWorldPtr) return nullptr;
        return RPM<UWorld*>(GWorldPtr);
    }

    inline UObject* FindObject(const std::string& name)
    {
        if (!GUObjectArray) return nullptr;
        const int32_t total = GUObjectArray->ObjObjects.NumElements;
        for (int32_t i = 0; i < total; ++i)
        {
            UObject* obj = GetObjectByIndex(i);
            if (!obj) continue;
            if (obj->GetName() == name)
                return obj;
        }
        return nullptr;
    }

    inline std::string GetFullName(const UObject* obj)
    {
        if (!obj) return "None";
        std::string name = obj->GetName();
        UObject* outer = RPM<UObject*>(
            reinterpret_cast<uintptr_t>(obj) + 0x20);
        while (outer)
        {
            name  = outer->GetName() + '.' + name;
            outer = RPM<UObject*>(
                reinterpret_cast<uintptr_t>(outer) + 0x20);
        }
        return name;
    }
} // namespace SDK

inline std::string UObject::GetFullName() const
{
    return SDK::GetFullName(this);
}

// ─────────────────────────────────────────────────────────────
//  AOB pattern scanner  (in-process, for injected DLL)
// ─────────────────────────────────────────────────────────────
inline uintptr_t PatternScan(uintptr_t start, size_t size,
    const char* pattern, const char* mask)
{
    const size_t patLen = strlen(mask);
    const uint8_t* mem  = reinterpret_cast<const uint8_t*>(start);

    for (size_t i = 0; i + patLen <= size; ++i)
    {
        bool found = true;
        for (size_t j = 0; j < patLen; ++j)
        {
            if (mask[j] == 'x' &&
                mem[i + j] != static_cast<uint8_t>(pattern[j]))
            {
                found = false;
                break;
            }
        }
        if (found) return start + i;
    }
    return 0;
}

// Resolve RIP-relative LEA/MOV to target address.
inline uintptr_t ResolveRIP(uintptr_t instrAddr,
    uint32_t instrOffset = 3,
    uint32_t instrSize   = 7)
{
    const int32_t disp = RPM<int32_t>(instrAddr + instrOffset);
    return instrAddr + instrSize + disp;
}

// ─────────────────────────────────────────────────────────────
//  Example init (call from DllMain / init thread):
//
//  HMODULE base = GetModuleHandleA("VALORANT-Win64-Shipping.exe");
//  MODULEINFO info{}; GetModuleInformation(GetCurrentProcess(), base, &info, sizeof(info));
//  uintptr_t start = (uintptr_t)base; size_t sz = info.SizeOfImage;
//
//  // GNamePoolData
//  uintptr_t nameHit  = PatternScan(start, sz,
//      "\x48\x8D\x05\x00\x00\x00\x00\x48\x8B\x08", "xxx????xxx");
//  uintptr_t nameBase = ResolveRIP(nameHit);
//
//  // GUObjectArray
//  uintptr_t objHit  = PatternScan(start, sz,
//      "\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x48\x8B\x40",
//      "xxx????xxxx?xxx");
//  uintptr_t objBase = ResolveRIP(objHit);
//
//  // GWorld
//  uintptr_t worldHit = PatternScan(start, sz,
//      "\x48\x8B\x1D\x00\x00\x00\x00\x48\x85\xDB", "xxx????xxx");
//  uintptr_t gWorldPtr = ResolveRIP(worldHit);
//
//  SDK::Init(nameBase, objBase, gWorldPtr);
//
//  NOTE: Rescan patterns from latest binary — Valorant updates frequently.
// ─────────────────────────────────────────────────────────────
