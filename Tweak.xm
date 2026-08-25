// rkreader — runtime IL2CPP recon for Rummikub (com.rummikubfree).
//
// Own-device analysis only. Injects into the game, resolves the exported
// il2cpp_* runtime API via dlsym, waits for the managed domain to come up, then
// dumps the Assembly-CSharp class/field map to a log so we can locate the tile
// model and the rack/board collections. Read-only: it does NOT modify game
// state. NOTE: online competition modes may have anti-cheat — test offline / vs
// AI to avoid risking the account.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <pthread.h>
#import <mach-o/dyld.h>
#import "rksolver.h"   // rk_solve(): Den Hertog-Hulshof DP, validated vs oracle

// ---- AppLovin MAX ad classes (minimal decls for hooking) ----
@interface MAInterstitialAd : NSObject @end
@interface MAAppOpenAd : NSObject @end
@interface MARewardedAd : NSObject @end
@interface MAAdView : UIView @end

// ---- il2cpp API (resolved at runtime) ----
typedef void*        (*t_domain_get)(void);
typedef void*        (*t_thread_attach)(void*);
typedef void**       (*t_domain_get_assemblies)(void*, size_t*);
typedef const void*  (*t_assembly_get_image)(const void*);
typedef const char*  (*t_image_get_name)(const void*);
typedef size_t       (*t_image_get_class_count)(const void*);
typedef const void*  (*t_image_get_class)(const void*, size_t);
typedef const char*  (*t_class_get_name)(void*);
typedef const char*  (*t_class_get_namespace)(void*);
typedef void*        (*t_class_get_fields)(void*, void**);
typedef const char*  (*t_field_get_name)(void*);
typedef size_t       (*t_field_get_offset)(void*);
typedef int          (*t_field_get_flags)(void*);
typedef void*        (*t_field_get_type)(void*);
typedef char*        (*t_type_get_name)(void*);
typedef void*        (*t_class_from_name)(const void*, const char*, const char*);
typedef const void*  (*t_class_get_methods)(void*, void**);
typedef const char*  (*t_method_get_name)(const void*);
typedef unsigned     (*t_method_get_param_count)(const void*);
typedef void*        (*t_method_get_return_type)(const void*);
typedef void*        (*t_method_get_param)(const void*, unsigned);
typedef unsigned     (*t_method_get_flags)(const void*, unsigned*);
typedef void         (*t_il2cpp_free)(void*);
typedef void*        (*t_class_get_method_from_name)(void*, const char*, int);
typedef size_t       (*t_array_length)(void*);
typedef uint16_t*    (*t_string_chars)(void*);
typedef int          (*t_string_length)(void*);
typedef void         (*t_MSHookFunction)(void*, void*, void**);
typedef void*        (*t_runtime_invoke)(const void*, void*, void**, void**);
typedef void*        (*t_class_get_type)(void*);
typedef void*        (*t_type_get_object)(void*);
typedef const void*  (*t_class_from_name2)(const void*, const char*, const char*);
typedef void*        (*t_object_new)(void*);
typedef void*        (*t_object_get_class)(void*);

static t_domain_get            f_domain_get;
static t_thread_attach         f_thread_attach;
static t_domain_get_assemblies f_domain_get_assemblies;
static t_assembly_get_image    f_assembly_get_image;
static t_image_get_name        f_image_get_name;
static t_image_get_class_count f_image_get_class_count;
static t_image_get_class       f_image_get_class;
static t_class_get_name        f_class_get_name;
static t_class_get_namespace   f_class_get_namespace;
static t_class_get_fields      f_class_get_fields;
static t_field_get_name        f_field_get_name;
static t_field_get_offset      f_field_get_offset;
static t_field_get_flags       f_field_get_flags;
static t_field_get_type        f_field_get_type;
static t_type_get_name         f_type_get_name;
static t_class_from_name        f_class_from_name;
static t_class_get_methods      f_class_get_methods;
static t_method_get_name        f_method_get_name;
static t_method_get_param_count f_method_get_param_count;
static t_method_get_return_type f_method_get_return_type;
static t_method_get_param       f_method_get_param;
static t_method_get_flags       f_method_get_flags;
static t_il2cpp_free            f_free;
static t_class_get_method_from_name f_class_get_method_from_name;
static t_array_length           f_array_length;
static t_string_chars           f_string_chars;
static t_string_length          f_string_length;
static t_MSHookFunction         f_MSHookFunction;
static t_runtime_invoke         f_runtime_invoke;
static t_class_get_type         f_class_get_type;
static t_type_get_object        f_type_get_object;
static t_object_new             f_object_new;
static t_object_get_class       f_object_get_class;
static const void *gAsmImg = NULL;   // Assembly-CSharp.dll
static const void *gCoreImg = NULL;  // UnityEngine.CoreModule.dll

// Sandboxed App Store apps can't write to /var/mobile; log inside the app's own
// container (always writable) and read it back as root over SSH.
static NSString *gLog = nil;

static void LOG(NSString *s) {
    if (!gLog) return;
    NSString *line = [s stringByAppendingString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gLog];
    if (!fh) { [line writeToFile:gLog atomically:NO encoding:NSUTF8StringEncoding error:nil]; return; }
    @try { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; }
    @finally { [fh closeFile]; }
}

// Handle to UnityFramework, obtained via RTLD_NOLOAD (no load is triggered, so
// there is no dyld-lock deadlock racing the app's own load of the framework).
static void *gUnity = NULL;
#define SYM(v, name) v = (typeof(v))dlsym(gUnity ? gUnity : RTLD_DEFAULT, name)

static BOOL resolveAPI(void) {
    SYM(f_domain_get, "il2cpp_domain_get");
    SYM(f_thread_attach, "il2cpp_thread_attach");
    SYM(f_domain_get_assemblies, "il2cpp_domain_get_assemblies");
    SYM(f_assembly_get_image, "il2cpp_assembly_get_image");
    SYM(f_image_get_name, "il2cpp_image_get_name");
    SYM(f_image_get_class_count, "il2cpp_image_get_class_count");
    SYM(f_image_get_class, "il2cpp_image_get_class");
    SYM(f_class_get_name, "il2cpp_class_get_name");
    SYM(f_class_get_namespace, "il2cpp_class_get_namespace");
    SYM(f_class_get_fields, "il2cpp_class_get_fields");
    SYM(f_field_get_name, "il2cpp_field_get_name");
    SYM(f_field_get_offset, "il2cpp_field_get_offset");
    SYM(f_field_get_flags, "il2cpp_field_get_flags");
    SYM(f_field_get_type, "il2cpp_field_get_type");
    SYM(f_type_get_name, "il2cpp_type_get_name");
    SYM(f_class_from_name, "il2cpp_class_from_name");
    SYM(f_class_get_methods, "il2cpp_class_get_methods");
    SYM(f_method_get_name, "il2cpp_method_get_name");
    SYM(f_method_get_param_count, "il2cpp_method_get_param_count");
    SYM(f_method_get_return_type, "il2cpp_method_get_return_type");
    SYM(f_method_get_param, "il2cpp_method_get_param");
    SYM(f_method_get_flags, "il2cpp_method_get_flags");
    SYM(f_free, "il2cpp_free");
    SYM(f_class_get_method_from_name, "il2cpp_class_get_method_from_name");
    SYM(f_array_length, "il2cpp_array_length");
    SYM(f_string_chars, "il2cpp_string_chars");
    SYM(f_string_length, "il2cpp_string_length");
    f_MSHookFunction = (t_MSHookFunction)dlsym(RTLD_DEFAULT, "MSHookFunction");
    SYM(f_runtime_invoke, "il2cpp_runtime_invoke");
    SYM(f_class_get_type, "il2cpp_class_get_type");
    SYM(f_type_get_object, "il2cpp_type_get_object");
    SYM(f_object_new, "il2cpp_object_new");
    SYM(f_object_get_class, "il2cpp_object_get_class");
    return f_domain_get && f_thread_attach && f_domain_get_assemblies &&
           f_assembly_get_image && f_image_get_name && f_image_get_class_count &&
           f_image_get_class && f_class_get_name && f_class_get_namespace &&
           f_class_get_fields && f_field_get_name && f_field_get_offset &&
           f_field_get_flags && f_field_get_type && f_type_get_name;
}

static NSString *missingSyms(void) {
    NSMutableArray *m = [NSMutableArray array];
    #define CHK(v) if(!v)[m addObject:@#v]
    CHK(f_domain_get);CHK(f_thread_attach);CHK(f_domain_get_assemblies);CHK(f_assembly_get_image);
    CHK(f_image_get_name);CHK(f_image_get_class_count);CHK(f_image_get_class);CHK(f_class_get_name);
    CHK(f_class_get_namespace);CHK(f_class_get_fields);CHK(f_field_get_name);CHK(f_field_get_offset);
    CHK(f_field_get_flags);CHK(f_field_get_type);CHK(f_type_get_name);
    #undef CHK
    return [m componentsJoinedByString:@","];
}

// Does the (lowercased) class name look game-model relevant?
static BOOL interesting(const char *nm) {
    if (!nm) return NO;
    if (nm[0] == '<') return NO;               // skip compiler-generated state machines
    NSString *n = [[NSString stringWithUTF8String:nm] lowercaseString];
    for (NSString *k in @[@"gamestate", @"gamelogic", @"gamemanager", @"gameplay",
                          @"rummikub", @"board", @"rack", @"deck", @"pool",
                          @"match", @"session", @"gameserver", @"gamemodel",
                          @"turn", @"gamedata"])
        if ([n containsString:k]) return YES;
    return NO;
}

static void dumpClass(void *klass) {
    const char *nm = f_class_get_name(klass);
    if (!nm || nm[0] == '<') return;
    const char *ns = f_class_get_namespace ? f_class_get_namespace(klass) : "";
    LOG([NSString stringWithFormat:@"CLASS %s%s%s",
         (ns && *ns) ? ns : "", (ns && *ns) ? "." : "", nm]);
    // Field name + offset + static flag only. We deliberately do NOT resolve
    // field TYPE names — il2cpp_type_get_name crashes on some generic/complex
    // field types, and offsets are what we need to read values later.
    void *iter = NULL, *field; int guard = 0;
    while ((field = f_class_get_fields(klass, &iter)) && guard++ < 256) {
        const char *fn = f_field_get_name(field);
        size_t off = f_field_get_offset ? f_field_get_offset(field) : 0;
        int flags = f_field_get_flags ? f_field_get_flags(field) : 0;
        BOOL isStatic = (flags & 0x10) != 0;   // FIELD_ATTRIBUTE_STATIC
        LOG([NSString stringWithFormat:@"    %@ off=0x%zx %s",
             isStatic ? @"[static]" : @"        ", off, fn ?: "?"]);
    }
}

// Grab a handle to UnityFramework ONLY if it is already loaded (RTLD_NOLOAD).
// This never triggers a load, so it cannot deadlock against the app's own
// concurrent load of the framework during startup.
static void tryGrabUnityHandle(void) {
    if (gUnity) return;
    NSString *fw = [[[NSBundle mainBundle] bundlePath]
        stringByAppendingPathComponent:@"Frameworks/UnityFramework.framework/UnityFramework"];
    gUnity = dlopen(fw.fileSystemRepresentation, RTLD_NOLOAD);
}

// Deep dump of one named class: field types + method signatures. Used only for
// well-behaved game-data classes (safe for type_get_name).
static void deepDump(const void *img, const char *cname) {
    if (!f_class_from_name) { LOG(@"DEEP: no class_from_name"); return; }
    void *k = f_class_from_name(img, "", cname);
    if (!k) { LOG([NSString stringWithFormat:@"DEEP %s: NOT FOUND", cname]); return; }
    LOG([NSString stringWithFormat:@"DEEP CLASS %s", cname]);
    void *it = NULL, *fld;
    while ((fld = f_class_get_fields(k, &it))) {
        const char *fn = f_field_get_name(fld);
        size_t off = f_field_get_offset(fld);
        int flags = f_field_get_flags(fld);
        char *tn = (f_field_get_type && f_type_get_name) ? f_type_get_name(f_field_get_type(fld)) : NULL;
        LOG([NSString stringWithFormat:@"  field %@0x%zx %s : %s",
             (flags & 0x10) ? @"[static] " : @"", off, fn ?: "?", tn ?: "?"]);
        if (tn && f_free) f_free(tn);
    }
    if (!f_class_get_methods) return;
    void *mit = NULL; const void *m;
    while ((m = f_class_get_methods(k, &mit))) {
        const char *mn = f_method_get_name ? f_method_get_name(m) : "?";
        unsigned pc = f_method_get_param_count ? f_method_get_param_count(m) : 0;
        unsigned iflags = 0; unsigned fl = f_method_get_flags ? f_method_get_flags(m, &iflags) : 0;
        char *rt = (f_method_get_return_type && f_type_get_name) ? f_type_get_name(f_method_get_return_type(m)) : NULL;
        NSMutableString *ps = [NSMutableString string];
        for (unsigned i = 0; i < pc && f_method_get_param && f_type_get_name; i++) {
            char *pt = f_type_get_name(f_method_get_param(m, i));
            if (i) [ps appendString:@","];
            [ps appendFormat:@"%s", pt ?: "?"];
            if (pt && f_free) f_free(pt);
        }
        LOG([NSString stringWithFormat:@"  method %@%s(%@) -> %s",
             (fl & 0x10) ? @"[static] " : @"", mn ?: "?", ps, rt ?: "?"]);
        if (rt && f_free) f_free(rt);
    }
}

// ================= Card reader =================
//
// RmkbGameData layout (from recon):
//   0xa0 Cards            : Card[]           (all 106 tiles)
//   0xb0 BoardCards       : List<Card>
//   0xc0 CardsByPlayerID  : Dictionary<string,List<Card>>
// Card:  0x10 OwnerPlayerID:String  0x1c Location:enum(0 Stack,1 Player,2 Board)  0x38 Value:CardValue*
// CardValue: 0x10 Color:int  0x14 NumericValue:int  0x18 IsJoker:bool

static void *gGameData = NULL;                    // captured live RmkbGameData*
static NSString *gCardsLog = nil;

static void CLOG(NSString *s) {
    if (!gCardsLog) return;
    NSString *line = [s stringByAppendingString:@"\n"];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gCardsLog];
    if (!fh) { [line writeToFile:gCardsLog atomically:NO encoding:NSUTF8StringEncoding error:nil]; return; }
    @try { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; }
    @finally { [fh closeFile]; }
}

// Hook on RmkbGameData::SetRackPositionsFromLocalData(self, other, str, method)
// to capture a live RmkbGameData instance pointer (`self`).
static bool (*orig_setrack)(void*, void*, void*, void*);
static bool hook_setrack(void *self, void *other, void *str, void *method) {
    gGameData = self;
    return orig_setrack(self, other, str, method);
}
// RmkbGameDataManipulator::CreateGrid(RmkbGameData) runs on match entry / board
// render, so this captures the live instance WITHOUT needing a tile move.
static void *gView = NULL;                   // live RmkbGameView3D (fires move events)
static void *gManip = NULL;                  // live RmkbGameDataManipulator (move applier)

static bool (*orig_creategrid)(void*, void*, void*);
static bool hook_creategrid(void *selfManip, void *gameData, void *method) {
    if (gameData) gGameData = gameData;
    if (selfManip) gManip = selfManip;       // needed to apply our own moves
    return orig_creategrid(selfManip, gameData, method);
}

static NSString *decodeString(void *s) {
    if (!s) return @"";
    int len = *(int*)((char*)s + 0x10);
    if (len < 0 || len > 8192) return @"";
    uint16_t *c = (uint16_t*)((char*)s + 0x14);
    return [NSString stringWithCharacters:c length:(NSUInteger)len];
}

static void dumpCards(void) {
    void *gd = gGameData;
    if (!gd) { CLOG(@"(no live game data captured yet — make a move / rearrange your rack, then re-trigger)"); return; }
    void *cardsArr = *(void**)((char*)gd + 0xa0);
    if (!cardsArr) { CLOG(@"(Cards array null)"); return; }
    size_t n = f_array_length ? f_array_length(cardsArr) : *(size_t*)((char*)cardsArr + 0x18);
    if (n > 1000) { CLOG([NSString stringWithFormat:@"(implausible card count %zu — aborting)", n]); return; }
    void **elems = (void**)((char*)cardsArr + 0x20);

    NSMutableDictionary<NSString*,NSMutableArray*> *buckets = [NSMutableDictionary dictionary];
    for (size_t i = 0; i < n; i++) {
        void *card = elems[i];
        if (!card) continue;
        int loc = *(int*)((char*)card + 0x1c);
        void *owner = *(void**)((char*)card + 0x10);
        void *val = *(void**)((char*)card + 0x38);
        if (!val) continue;
        int color = *(int*)((char*)val + 0x10);
        int num   = *(int*)((char*)val + 0x14);
        bool joker = *(bool*)((char*)val + 0x18);
        NSString *ownerStr = decodeString(owner);
        NSString *bucket = loc == 2 ? @"BOARD" :
                           loc == 0 ? @"STACK" :
                           [NSString stringWithFormat:@"RACK[%@]", ownerStr.length ? ownerStr : @"?"];
        static const char *COLORS[4] = { "Black", "Blue", "Red", "Yellow" };
        NSString *tile = joker ? @"Joker"
            : [NSString stringWithFormat:@"%s-%d",
               (color >= 0 && color < 4) ? COLORS[color] : "C?", num + 1];
        NSMutableArray *arr = buckets[bucket];
        if (!arr) { arr = [NSMutableArray array]; buckets[bucket] = arr; }
        [arr addObject:tile];
    }
    CLOG([NSString stringWithFormat:@"===== snapshot (%zu cards) tile=c<color>-<number>, JK=joker =====", n]);
    for (NSString *k in [buckets.allKeys sortedArrayUsingSelector:@selector(compare:)]) {
        NSArray *a = buckets[k];
        CLOG([NSString stringWithFormat:@"%@ (%lu): %@", k, (unsigned long)a.count,
              [a componentsJoinedByString:@" "]]);
    }
    CLOG(@"===== end snapshot =====");
}

static void installCaptureHook(const void *img) {
    static BOOL installed = NO;
    if (installed) return;
    if (!f_MSHookFunction || !f_class_from_name || !f_class_get_method_from_name) {
        LOG(@"[rkreader] cannot hook (missing MSHookFunction/class APIs)"); return;
    }
    void *k = f_class_from_name(img, "", "RmkbGameData");
    if (!k) { LOG(@"[rkreader] RmkbGameData class not found for hook"); return; }
    void *m = f_class_get_method_from_name(k, "SetRackPositionsFromLocalData", 2);
    if (!m) { LOG(@"[rkreader] SetRackPositionsFromLocalData not found"); return; }
    void *fp = *(void**)m;                     // MethodInfo.methodPointer (offset 0)
    if (fp) { f_MSHookFunction(fp, (void*)hook_setrack, (void**)&orig_setrack);
              LOG([NSString stringWithFormat:@"[rkreader] hook setrack @ %p", fp]); }
    // Also hook CreateGrid on the manipulator for capture without a tile move.
    void *mk = f_class_from_name(img, "", "RmkbGameDataManipulator");
    if (mk) {
        // Do NOT hook the move path to observe payloads. Three attempts each
        // crashed the game on a real drag: ValidateAndApplyMove returns a
        // value type (indirect x8 return, corrupted by a pointer-returning
        // hook), and FireMoveMadeEvent/PrepareTileObjects were read at fixed
        // offsets that do not hold for every payload the game passes. The move
        // pipeline has to be understood from a static decompile first.
        void *m2 = f_class_get_method_from_name(mk, "CreateGrid", 1);
        if (m2) { void *fp2 = *(void**)m2;
                  if (fp2) { f_MSHookFunction(fp2, (void*)hook_creategrid, (void**)&orig_creategrid);
                             LOG([NSString stringWithFormat:@"[rkreader] hook CreateGrid @ %p", fp2]); } }
    }
    installed = YES;
}

static const void *assemblyCSharpImage(void *domain) {
    size_t nas = 0; void **assemblies = f_domain_get_assemblies(domain, &nas);
    for (size_t a = 0; a < nas; a++) {
        const void *img = f_assembly_get_image(assemblies[a]);
        if (!img) continue;
        const char *iname = f_image_get_name ? f_image_get_name(img) : NULL;
        if (iname && strcmp(iname, "Assembly-CSharp.dll") == 0) return img;
    }
    return NULL;
}

static void reconThread(void) {
    // Auto-install the capture hooks (no trigger, no tile move needed). Wait for
    // il2cpp to be up AND stable (assembly count steady) so we don't touch
    // half-built tables during startup, then attach and hook.
    LOG(@"[rkreader] capture thread: waiting for il2cpp…");
    BOOL resolved = NO;
    for (int i = 0; i < 1800 && !resolved; i++) { tryGrabUnityHandle(); resolved = resolveAPI(); usleep(100000); }
    LOG([NSString stringWithFormat:@"[rkreader] resolved=%d unity=%p missing=%@", resolved, gUnity, missingSyms()]);
    if (!resolved) return;
    void *domain = NULL;
    for (int i = 0; i < 1800 && !domain; i++) { domain = f_domain_get(); if (!domain) usleep(100000); }
    LOG([NSString stringWithFormat:@"[rkreader] domain=%p", domain]);
    if (!domain) return;
    f_thread_attach(domain);
    long prev = -1; int stable = 0; long lastn = 0;
    for (int i = 0; i < 240; i++) {           // up to ~120s
        size_t n = 0; f_domain_get_assemblies(domain, &n); lastn = (long)n;
        if ((long)n > 50 && (long)n == prev) { if (++stable >= 4) break; }
        else stable = 0;
        prev = (long)n;
        usleep(500000);
    }
    LOG([NSString stringWithFormat:@"[rkreader] assemblies stable ~%ld", lastn]);
    const void *img = assemblyCSharpImage(domain);
    LOG([NSString stringWithFormat:@"[rkreader] img=%p", img]);
    if (!img) return;
    gAsmImg = img;
    // also locate UnityEngine.CoreModule for Object/Camera/Transform APIs
    { size_t nas2 = 0; void **as2 = f_domain_get_assemblies(domain, &nas2);
      for (size_t a = 0; a < nas2; a++) { const void *im = f_assembly_get_image(as2[a]);
        const char *nm = im && f_image_get_name ? f_image_get_name(im) : NULL;
        if (nm && strcmp(nm, "UnityEngine.CoreModule.dll") == 0) { gCoreImg = im; break; } } }
    LOG([NSString stringWithFormat:@"[rkreader] coreImg=%p", gCoreImg]);
    installCaptureHook(img);
    LOG(@"[rkreader] capture hooks armed; SOLVE ready");
}

static void *reconEntry(void *unused) { @autoreleasepool { reconThread(); } return NULL; }

// ================= Ad suppression (AppLovin MAX) =================
// Blocks fullscreen interstitials, app-open ads and banners by no-op'ing the
// SDK's public show/load entry points. Rewarded ads are intentionally left
// intact (blocking them would also withhold the in-game reward they grant).

%group ALHooks
%hook MAInterstitialAd
- (void)showAd { LOG(@"[ads] blocked interstitial showAd"); }
- (void)showAdForPlacement:(id)p { LOG(@"[ads] blocked interstitial showAdForPlacement:"); }
- (void)showAdForPlacement:(id)p customData:(id)c { LOG(@"[ads] blocked interstitial showAdForPlacement:customData:"); }
- (void)showAdForPlacement:(id)p customData:(id)c viewController:(id)vc { LOG(@"[ads] blocked interstitial (vc)"); }
%end
%hook MAAppOpenAd
- (void)showAd { LOG(@"[ads] blocked appopen showAd"); }
- (void)showAdForPlacement:(id)p { LOG(@"[ads] blocked appopen showAdForPlacement:"); }
- (void)showAdForPlacement:(id)p customData:(id)c { LOG(@"[ads] blocked appopen showAdForPlacement:customData:"); }
- (void)showAdForPlacement:(id)p customData:(id)c viewController:(id)vc { LOG(@"[ads] blocked appopen (vc)"); }
%end
%hook MAAdView
- (void)loadAd { LOG(@"[ads] blocked banner loadAd"); }
%end
%end  // group ALHooks

// Diagnostic: log every modal presentation so we can identify the real ad VC.
// Blocking AppLovin's show methods was not enough: MAX is only the mediation
// layer, and the ad that actually appeared came from Pangle
// (PAGRewardedInterstitialRootViewController in the log) whose entry points we
// never touched. Refuse to present any ad SDK's view controller instead — that
// catches whichever network mediation picks, without needing a hook per SDK.
static BOOL rkIsAdViewController(NSString *cn) {
    static NSArray *marks = nil;
    if (!marks) marks = @[ @"PAG", @"GAD", @"MAX", @"ALInter", @"AppLovin", @"Pangle",
                           @"IronSource", @"Vungle", @"AdColony", @"Mintegral",
                           @"Chartboost", @"Tapjoy", @"Fyber", @"UnityAds", @"Admob" ];
    for (NSString *m in marks) if ([cn rangeOfString:m].location != NSNotFound) return YES;
    return NO;
}

%group VCDiag
%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)a completion:(void(^)(void))c {
    NSString *cn = vc ? NSStringFromClass([vc class]) : @"nil";
    if (rkIsAdViewController(cn)) {
        LOG([@"[ads] blocked presentation: " stringByAppendingString:cn]);
        if (c) c();                       // let the caller's completion run
        return;
    }
    LOG([@"[ads] present VC: " stringByAppendingString:cn]);
    %orig(vc, a, c);
}
%end
%end  // group VCDiag

static void adWaitAndInit(void) {
    for (int i = 0; i < 900; i++) {          // up to ~90s
        if (NSClassFromString(@"MAInterstitialAd") || NSClassFromString(@"MAAdView")) {
            %init(ALHooks);
            LOG(@"[ads] AppLovin hooks installed");
            return;
        }
        usleep(100000);
    }
    LOG(@"[ads] AppLovin classes never appeared");
}
static void *adEntry(void *unused) { @autoreleasepool { adWaitAndInit(); } return NULL; }

// ================= Solver bridge =================
// Read the live RmkbGameData into solver inputs and run rk_solve(). Must be
// called on the Unity/main thread (where reading managed memory is safe).
// Build solver input directly from the gathered on-screen tiles (always current,
// reflects sorting/moves; no gGameData capture needed).
static id rkComputeFromTiles(NSArray<NSDictionary*> *tiles) {
    if (!tiles.count) return @"타일을 못 읽음 — 매치 화면에서 다시.";
    int board[NCOL][NNUM + 1], rack[NCOL][NNUM + 1];
    memset(board, 0, sizeof(board)); memset(rack, 0, sizeof(rack));
    int jb = 0, jr = 0;
    for (NSDictionary *t in tiles) {
        int loc = [t[@"loc"] intValue], color = [t[@"c"] intValue], num = [t[@"n"] intValue];
        BOOL joker = [t[@"j"] boolValue], mine = [t[@"mine"] boolValue];
        if (loc == 2) {                                 // Board
            if (joker) jb++;
            else if (color >= 0 && color < NCOL && num >= 1 && num <= NNUM) board[color][num]++;
        } else if (loc == 1 && mine) {                  // my rack
            if (joker) jr++;
            else if (color >= 0 && color < NCOL && num >= 1 && num <= NNUM) rack[color][num]++;
        }
    }
    // Sanity check the split: a rack far larger than a real hand means opponents'
    // tiles leaked into the solver input.
    int nBoard = 0, nMine = 0, nOther = 0;
    for (NSDictionary *t in tiles) {
        int loc = [t[@"loc"] intValue];
        if (loc == 2) nBoard++;
        else if (loc == 1) ([t[@"mine"] boolValue] ? nMine++ : nOther++);
    }
    LOG([NSString stringWithFormat:@"[solve] board=%d myRack=%d otherRacks=%d", nBoard, nMine, nOther]);

    static char place[4096], sets[8000];
    int placed = rk_solve(board, rack, jb, jr, place, sizeof(place), sets, sizeof(sets));
    if (placed < 0) return @{ @"error": @"보드를 유효하게 배열할 수 없음." };
    return @{ @"placed": @(placed),
              @"place": [NSString stringWithUTF8String:place],
              @"sets":  [NSString stringWithUTF8String:sets] };
}

// ================= Tile gather (screen coords via Unity camera) =================
// Returns an array of dicts: {color,num,joker,loc,owner,x,y} with x,y in UIKit
// points. Must run on the Unity/main thread.
// Resolve il2cpp + locate the images we need, on demand (safe on the main thread
// once the game is running). Removes any dependency on the capture thread.
static BOOL ensureImages(void) {
    if (gAsmImg && gCoreImg) return YES;
    tryGrabUnityHandle();
    if (!resolveAPI()) return NO;
    void *dom = f_domain_get(); if (!dom) return NO;
    if (f_thread_attach) f_thread_attach(dom);
    size_t n = 0; void **as = f_domain_get_assemblies(dom, &n);
    for (size_t a = 0; a < n; a++) {
        const void *im = f_assembly_get_image(as[a]);
        const char *nm = (im && f_image_get_name) ? f_image_get_name(im) : NULL;
        if (!nm) continue;
        if (!gAsmImg  && strcmp(nm, "Assembly-CSharp.dll") == 0) gAsmImg = im;
        if (!gCoreImg && strcmp(nm, "UnityEngine.CoreModule.dll") == 0) gCoreImg = im;
    }
    return gAsmImg && gCoreImg;
}

// The capture hooks used to be installed only from the background recon thread,
// which blocks indefinitely inside il2cpp_domain_get() on some launches — in
// those runs no hook ever got installed (observed: log had no "hook ..." lines
// at all), so gGameData/gManip stayed null and auto-place had nothing to drive.
// Install them from the main thread instead, off the same proven path SOLVE uses.
static void ensureHooksMainThread(void) {
    static BOOL tried = NO;
    if (tried || !ensureImages()) return;
    tried = YES;
    installCaptureHook(gAsmImg);
}

// ---- move application ----
// A move is: card IDs + destination. Build the same RmkbMovesData a real drag
// produces and hand it to the game's own validator, so legality, turn state and
// animation all stay the game's business.
//   RmkbMovesData: 0x10 TypeOfMove, 0x14 MoveMakingSeat, 0x18 MoveDetails,
//   0x1c TargetLocation, 0x20 TargetX, 0x24 TargetY, 0x28 PreferredCardToAttatchTo,
//   0x2c isAIMove, 0x30 MovedCards:List<int>
// Enums: MoveType.PlayerAction=0; RmkbMoveDetails.MoveTiles=0; CardLocation Board=2.
// Build one move carrying a whole set. MovedCards is a List<int> precisely
// because a move is meant to relocate several tiles at once; issuing one move
// per tile makes every intermediate board state a broken set, which the game
// validates and refuses. Placing tiles one at a time only ever worked into empty
// space far from other tiles.
// Build the move exactly the way OnMouseUp does (decompiled):
//   md = new RmkbMovesData()            // ctor only
//   md.TargetLocation = 2               // 0x1c
//   md.TargetPositionX/Y = cell         // 0x20 / 0x24, written as one 8-byte pair
//   for each card: MovedCards.Add(id) and card.MoveType = 2   // Card 0x34
// It never touches TypeOfMove, MoveMakingSeat, MoveDetails or
// PreferredCardToAttatchTo — earlier builds filled those in by guesswork, and the
// per-card MoveType write was missing entirely, which is the step the game does
// before firing the event.
static void *rkBuildMove(NSArray *tilesOfSet, int targetX, int targetY, int attachTo) {
    if (!tilesOfSet.count) return NULL;
    if (!f_object_new || !f_object_get_class || !f_class_from_name ||
        !f_class_get_method_from_name || !f_runtime_invoke) return NULL;
    void *cls = f_class_from_name(gAsmImg, "", "RmkbMovesData");
    if (!cls) { LOG(@"[auto] RmkbMovesData class not found"); return NULL; }
    void *md = f_object_new(cls);
    if (!md) { LOG(@"[auto] object_new failed"); return NULL; }
    void *ctor = f_class_get_method_from_name(cls, ".ctor", 0);
    if (ctor) { void *exc = NULL; f_runtime_invoke(ctor, md, NULL, &exc);
                if (exc) { LOG(@"[auto] .ctor threw"); return NULL; } }
    void *lst = *(void**)((char*)md + 0x30);
    if (!lst) { LOG(@"[auto] MovedCards null after ctor"); return NULL; }
    void *lcls = f_object_get_class(lst);
    void *mAdd = lcls ? f_class_get_method_from_name(lcls, "Add", 1) : NULL;
    if (!mAdd) { LOG(@"[auto] List.Add not found"); return NULL; }
    for (NSDictionary *t in tilesOfSet) {
        int idv = [t[@"id"] intValue];
        void *args[1] = { &idv }; void *exc = NULL;
        f_runtime_invoke(mAdd, lst, args, &exc);
        if (exc) { LOG(@"[auto] List.Add threw"); return NULL; }
        void *card = (void *)(uintptr_t)[t[@"cptr"] unsignedLongLongValue];
        if (card) *(int*)((char*)card + 0x34) = 2;      // Card.MoveType, as the game sets
    }
    *(int*)((char*)md + 0x1c) = 2;                       // TargetLocation = Board
    *(int*)((char*)md + 0x20) = targetX;
    *(int*)((char*)md + 0x24) = targetY;
    // The game decides the final column itself (observed: tiles landed one cell
    // away from the requested one, still forming the right set). Naming the card
    // to attach to lets it place the tile in the intended set rather than having
    // us fight it over an exact cell.
    if (attachTo > 0) *(int*)((char*)md + 0x28) = attachTo;
    return md;
}

// Apply through the view's move event — the same entry point OnMouseUp uses at
// the end of a real drag — so validation, turn state and the on-screen refresh
// all run. Calling ValidateAndApplyMove directly (first attempt) returned without
// an exception but nothing moved on screen: it only mutates game data, and the
// redraw lives further up the pipeline.
// Apply a move, then repaint. FireMoveMadeEvent alone never landed a tile — it is
// only a notification. ValidateAndApplyMove is what mutates the game data (an
// early test returned a validation state with no exception, which was misread as
// a failure because nothing moved on screen), and PrepareTileObjects rebuilds the
// tiles from that data. Note these are *calls*; hooking either one crashed the
// game, calling them never has.
static void *rkFindObject(const void *img, const char *ns, const char *name);  // defined below
// Apply via the view's move event. This is the path a real drag ends on, and it
// is the only one observed to actually relocate tiles on screen. Driving
// ValidateAndApplyMove directly updated nothing visible and, with the commit flag
// on, still left the model untouched.
static BOOL rkApplyMove(void *md) {
    if (!md) return NO;
    if (!gView) gView = rkFindObject(gAsmImg, "", "RmkbGameView3D");
    if (!gView) { LOG(@"[auto] no view"); return NO; }
    void *vcls = f_class_from_name(gAsmImg, "", "RmkbGameView3D");
    void *mFire = vcls ? f_class_get_method_from_name(vcls, "FireMoveMadeEvent", 1) : NULL;
    if (!mFire) { LOG(@"[auto] FireMoveMadeEvent not found"); return NO; }
    void *args[1] = { md };
    void *exc = NULL;
    f_runtime_invoke(mFire, gView, args, &exc);
    return exc == NULL;
}

// Move the 3D tiles to match the board data. ValidateAndApplyMove updates the
// model (and the container's CurrentPosition), but nothing repositions the
// objects, so AUTO looked like it did nothing while the pending list drained.
//
// Self-calibrating on purpose: GetBoardWorldPosition's argument convention
// (absolute 100-based cell vs board-relative) is not documented anywhere we can
// see, so first check it against a tile that is already sitting still. Only if
// the computed world position matches that tile's actual transform do we move
// anything — a wrong convention would fling every tile to a bogus spot.
static void rkSyncVisuals(void) {
    if (!gView || !ensureImages()) return;
    void *vcls = f_class_from_name(gAsmImg, "", "RmkbGameView3D");
    void *trC  = f_class_from_name(gCoreImg, "UnityEngine", "Transform");
    void *mWorld = vcls ? f_class_get_method_from_name(vcls, "GetBoardWorldPosition", 2) : NULL;
    void *mGetPos = trC ? f_class_get_method_from_name(trC, "get_position", 0) : NULL;
    void *mSetPos = trC ? f_class_get_method_from_name(trC, "set_position", 1) : NULL;
    if (!mWorld || !mGetPos || !mSetPos) { LOG(@"[sync] missing transform/world methods"); return; }

    int bOrgX = 100, bOrgY = 100;                         // board origin (RmkbGameData)
    if (gGameData) {
        bOrgX = *(int*)((char*)gGameData + 0x90);
        bOrgY = *(int*)((char*)gGameData + 0x98);
    }
    void *arr = *(void**)((char*)gView + 0x140);          // Tiles : TileContainer[]
    size_t cnt = (arr && f_array_length) ? f_array_length(arr) : 0;
    if (!cnt) { LOG(@"[sync] no tiles"); return; }
    void **elems = (void**)((char*)arr + 0x20);

    BOOL calibrated = NO;
    int moved = 0;
    for (size_t pass = 0; pass < 2; pass++) {            // pass 0 = calibrate, 1 = apply
        for (size_t i = 0; i < cnt; i++) {
            void *tc = elems[i]; if (!tc) continue;
            void *transform = *(void**)((char*)tc + 0x48); if (!transform) continue;
            // Drive this from the Card (the model), not the container's
            // CurrentPosition: applying a move updates the card, while the
            // container's copy is only refreshed by the view's own arrange pass,
            // which never runs here. Reading the container made every tile look
            // "already in place" and repositioned nothing.
            void *card = *(void**)((char*)tc + 0x40); if (!card) continue;
            if (*(int*)((char*)card + 0x1c) != 2) continue;   // Card.Location != Board
            // Board-origin-relative, measured: for cell(101,103) the tile sits at
            // world (-4.61,-0.14) and GetBoardWorldPosition(1,3) returns exactly
            // that, while passing the absolute cell returns (100.39,-160.14).
            float gx = (float)(*(int*)((char*)card + 0x20) - bOrgX);
            float gy = (float)(*(int*)((char*)card + 0x24) - bOrgY);
            void *exc = NULL;
            void *wargs[2] = { &gx, &gy };
            void *wbox = f_runtime_invoke(mWorld, gView, wargs, &exc);
            if (exc || !wbox) continue;
            float *w = (float*)((char*)wbox + 0x10);
            void *pbox = f_runtime_invoke(mGetPos, transform, NULL, &exc);
            if (exc || !pbox) continue;
            float *p = (float*)((char*)pbox + 0x10);
            float d = fabsf(w[0]-p[0]) + fabsf(w[1]-p[1]) + fabsf(w[2]-p[2]);
            if (pass == 0) {
                if (d < 0.05f) {                           // this tile is already where the formula says
                    calibrated = YES;
                    LOG([NSString stringWithFormat:@"[sync] calibration OK at cell(%d,%d) delta=%.3f",
                         (int)gx, (int)gy, d]);
                    break;
                }
                continue;
            }
            if (d < 0.01f) continue;                       // already in place
            float wpos[3] = { w[0], w[1], w[2] };
            void *sargs[1] = { wpos };
            f_runtime_invoke(mSetPos, transform, sargs, &exc);
            *(float*)((char*)tc + 0x50) = w[0];             // CurrentTargetPosition, so the
            *(float*)((char*)tc + 0x54) = w[1];             // tween does not drag it back
            *(float*)((char*)tc + 0x58) = w[2];
            // Keep the container's own bookkeeping in step with the card, so the
            // "did this move land?" check (which reads these) can settle.
            *(int*)((char*)tc + 0x6c) = *(int*)((char*)card + 0x20);
            *(int*)((char*)tc + 0x70) = *(int*)((char*)card + 0x24);
            *(int*)((char*)tc + 0x80) = *(int*)((char*)card + 0x1c);
            if (!exc) moved++;
        }
        if (pass == 0 && !calibrated) {
            LOG(@"[sync] calibration failed — not moving anything");
            return;
        }
    }
    LOG([NSString stringWithFormat:@"[sync] repositioned %d tiles", moved]);
}

// Find the first live instance of a UnityEngine.Object subclass, the same way the
// tile gather locates the view.
static void *rkFindObject(const void *img, const char *ns, const char *name) {
    if (!ensureImages() || !f_runtime_invoke || !f_class_get_type || !f_type_get_object) return NULL;
    void *objC = f_class_from_name(gCoreImg, "UnityEngine", "Object");
    void *mFind = objC ? f_class_get_method_from_name(objC, "FindObjectsOfTypeAll", 1) : NULL;
    void *cls = f_class_from_name(img, ns, name);
    if (!mFind || !cls) return NULL;
    void *pv[1] = { f_type_get_object(f_class_get_type(cls)) };
    void *exc = NULL;
    void *arr = f_runtime_invoke(mFind, NULL, pv, &exc);
    if (exc || !arr) return NULL;
    size_t n = f_array_length ? f_array_length(arr) : 0;
    if (!n) return NULL;
    return *(void**)((char*)arr + 0x20);
}

// Board bounds. The capture hooks only fire on match entry / tile move, so a
// match already in progress leaves gGameData null — don't depend on it. Prefer
// the manipulator's own grid fields (0x60 _gridWidth, 0x64 _gridHeight,
// 0x68 _boardStartX, 0x6c _boardStartY), and fall back to the extents of the
// tiles we can already see.
static BOOL rkBoardBounds(NSArray *tiles, int *x0, int *w, int *y0, int *h) {
    // RmkbGameData's BoardSize* is the authoritative *playable* rectangle.
    // Do NOT use the manipulator's _grid — that is a 200x200 backing store, and
    // trusting it put test tiles at x=115, off to the side of the real board.
    if (gGameData) {
        int sx = *(int*)((char*)gGameData + 0x90), gw = *(int*)((char*)gGameData + 0x94);
        int sy = *(int*)((char*)gGameData + 0x98), gh = *(int*)((char*)gGameData + 0x9c);
        if (gw > 0 && gh > 0 && gw < 64 && gh < 64) {
            *x0 = sx; *w = gw; *y0 = sy; *h = gh;
            LOG([NSString stringWithFormat:@"[auto] board(gameData) x0=%d w=%d y0=%d h=%d", sx, gw, sy, gh]);
            return YES;
        }
    }
    // No tile-extent fallback: stray tiles outside the play area dragged the
    // inferred origin to x=99 and every queued target landed off-board, so the
    // game refused the lot. Better to refuse to run than to aim at nothing.
    LOG(@"[auto] board bounds unavailable (game data not captured)");
    return NO;
}

static NSArray<NSDictionary*> *rkGatherTiles(CGFloat winHpoints, CGFloat scale) {
    if (!ensureImages()) { return nil; }
    if (!f_runtime_invoke || !f_class_get_type || !f_type_get_object ||
        !f_class_from_name || !f_class_get_method_from_name) { return nil; }
    void *objC = f_class_from_name(gCoreImg, "UnityEngine", "Object");
    void *camC = f_class_from_name(gCoreImg, "UnityEngine", "Camera");
    void *trC  = f_class_from_name(gCoreImg, "UnityEngine", "Transform");
    void *viewC = f_class_from_name(gAsmImg, "", "RmkbGameView3D");
    if (!objC || !camC || !trC || !viewC) return nil;
    void *mFind = f_class_get_method_from_name(objC, "FindObjectsOfTypeAll", 1);
    void *mMain = f_class_get_method_from_name(camC, "get_main", 0);
    void *mW2S  = f_class_get_method_from_name(camC, "WorldToScreenPoint", 1);
    void *mPos  = f_class_get_method_from_name(trC,  "get_position", 0);
    if (!mFind || !mMain || !mW2S || !mPos) return nil;

    void *exc = NULL;
    void *vType = f_type_get_object(f_class_get_type(viewC));
    void *pv[1] = { vType };
    void *varr = f_runtime_invoke(mFind, NULL, pv, &exc);
    size_t vn = (varr && f_array_length) ? f_array_length(varr) : 0;
    if (!varr || vn == 0) return nil;
    void *view = *(void**)((char*)varr + 0x20);
    gView = view;                                        // reused to fire move events
    void *arr = *(void**)((char*)view + 0x140);          // Tiles : TileContainer[]
    size_t cnt = (arr && f_array_length) ? f_array_length(arr) : 0;
    if (!arr || cnt == 0) return nil;
    void *cam = f_runtime_invoke(mMain, NULL, NULL, &exc);
    if (!cam) { return nil; }

    NSMutableArray *out = [NSMutableArray array];
    void **elems = (void**)((char*)arr + 0x20);
    for (size_t i = 0; i < cnt; i++) {
        void *tcInst = elems[i]; if (!tcInst) continue;
        void *transform = *(void**)((char*)tcInst + 0x48);
        void *card = *(void**)((char*)tcInst + 0x40);
        if (!transform || !card) continue;
        int loc = *(int*)((char*)card + 0x1c);
        void *owner = *(void**)((char*)card + 0x10);
        void *val = *(void**)((char*)card + 0x38); if (!val) continue;
        int color = *(int*)((char*)val + 0x10);
        int num = *(int*)((char*)val + 0x14) + 1;
        bool joker = *(bool*)((char*)val + 0x18);
        // Card layout (recon): 0x18 CardID, 0x20 PositionX, 0x24 PositionY. These
        // are the grid coords a move targets, so read them here (same object we
        // already touch) rather than hooking the move path.
        int cardID = *(int*)((char*)card + 0x18);
        int posX = *(int*)((char*)card + 0x20);
        int posY = *(int*)((char*)card + 0x24);
        // The Card the container points at does not necessarily get updated when a
        // move is applied (the game works on its own copy), which made auto-place
        // think a tile never arrived and re-issue the same move forever. The
        // container's own CurrentPosition/CurrentLocation is what is on screen.
        int curX = *(int*)((char*)tcInst + 0x6c);
        int curY = *(int*)((char*)tcInst + 0x70);
        int curLoc = *(int*)((char*)tcInst + 0x80);
        exc = NULL;
        void *posBox = f_runtime_invoke(mPos, transform, NULL, &exc); if (!posBox) continue;
        float *wp = (float*)((char*)posBox + 0x10);
        float world[3] = { wp[0], wp[1], wp[2] };
        void *pW2S[1] = { world };
        void *scrBox = f_runtime_invoke(mW2S, cam, pW2S, &exc); if (!scrBox) continue;
        float *sp = (float*)((char*)scrBox + 0x10);
        if (sp[2] <= 0) continue;                         // behind camera
        CGFloat x = sp[0] / scale;
        CGFloat y = winHpoints - sp[1] / scale;           // flip Unity y-up -> UIKit
        NSString *os = owner ? decodeString(owner) : @"";
        BOOL faceUp = *(bool*)((char*)tcInst + 0x5c);     // TileContainer.IsFaceUp
        [out addObject:@{ @"c": @(color), @"n": @(num), @"j": @(joker),
                          @"loc": @(loc), @"owner": os, @"up": @(faceUp),
                          @"id": @(cardID), @"gx": @(posX), @"gy": @(posY),
                          @"cptr": @((uintptr_t)card),
                          @"cx": @(curX), @"cy": @(curY), @"cloc": @(curLoc),
                          @"p": [NSValue valueWithCGPoint:CGPointMake(x, y)] }];
    }

    // Whose rack is whose. This used to be "owner does not start with AI_", which
    // silently folded every human opponent's hand into my own and fed the solver
    // tiles I do not hold. Only my own rack is dealt face up, so the owner of the
    // face-up rack tiles is me — identify that id first, then classify by id (so a
    // tile that is briefly face down mid-deal is still recognised as mine).
    NSCountedSet *faceUpOwners = [NSCountedSet set];
    for (NSDictionary *t in out)
        if ([t[@"loc"] intValue] == 1 && [t[@"up"] boolValue] && [t[@"owner"] length])
            [faceUpOwners addObject:t[@"owner"]];
    NSString *myID = nil; NSUInteger best = 0;
    for (NSString *o in faceUpOwners)
        if ([faceUpOwners countForObject:o] > best) { best = [faceUpOwners countForObject:o]; myID = o; }

    NSMutableArray *res = [NSMutableArray arrayWithCapacity:out.count];
    for (NSDictionary *t in out) {
        NSString *o = t[@"owner"];
        BOOL mine = myID ? [o isEqualToString:myID]
                         : !(o.length >= 3 && [o hasPrefix:@"AI_"]);   // pre-deal fallback
        NSMutableDictionary *m = [t mutableCopy];
        m[@"mine"] = @(mine);
        [res addObject:m];
    }
    static NSString *lastMyID = nil;
    if (myID && ![myID isEqualToString:lastMyID]) {
        lastMyID = myID;
        LOG([NSString stringWithFormat:@"[gather] my player id = %@ (%lu face-up rack tiles)",
             myID, (unsigned long)best]);
    }
    return res;
}

// ================= On-screen overlay (button + result panel) =================
// A dedicated top-level window that passes touches through EXCEPT on its own
// controls, so the game keeps working while our button/panel stay visible+tappable.
// A transparent view that draws highlight rings on tiles to play + polylines
// connecting each recommended set. Non-interactive (touches pass through).
@interface RKDrawView : UIView
@property (nonatomic, strong) NSArray *highlights;  // dicts {p:NSValue, color:UIColor}
@property (nonatomic, strong) NSArray *lines;       // dicts {pts:NSArray<NSValue>, color:UIColor}
@end
@implementation RKDrawView
- (void)drawRect:(CGRect)r {
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    for (NSDictionary *ln in self.lines) {
        NSArray *pts = ln[@"pts"]; if (pts.count < 2) continue;
        UIColor *col = ln[@"color"] ?: [UIColor whiteColor];
        CGContextSetStrokeColorWithColor(ctx, col.CGColor);
        CGContextSetLineWidth(ctx, 4); CGContextSetLineCap(ctx, kCGLineCapRound); CGContextSetLineJoin(ctx, kCGLineJoinRound);
        CGContextSetShadowWithColor(ctx, CGSizeZero, 4, [UIColor blackColor].CGColor);
        for (NSUInteger i = 0; i < pts.count; i++) {
            CGPoint p = [pts[i] CGPointValue];
            if (i == 0) CGContextMoveToPoint(ctx, p.x, p.y); else CGContextAddLineToPoint(ctx, p.x, p.y);
        }
        CGContextStrokePath(ctx);
        CGContextSetShadowWithColor(ctx, CGSizeZero, 0, NULL);
        // dots at each node
        for (NSValue *v in pts) { CGPoint p = [v CGPointValue];
            CGContextSetFillColorWithColor(ctx, col.CGColor);
            CGContextFillEllipseInRect(ctx, CGRectMake(p.x-4, p.y-4, 8, 8)); }
        // numbered badge (step order) near the first node
        NSNumber *num = ln[@"num"];
        if (num) {
            CGPoint p0 = [pts[0] CGPointValue];
            CGRect badge = CGRectMake(p0.x - 26, p0.y - 14, 24, 24);
            CGContextSetFillColorWithColor(ctx, col.CGColor);
            CGContextFillEllipseInRect(ctx, badge);
            CGContextSetStrokeColorWithColor(ctx, [UIColor whiteColor].CGColor);
            CGContextSetLineWidth(ctx, 2); CGContextStrokeEllipseInRect(ctx, badge);
            NSDictionary *at = @{ NSFontAttributeName: [UIFont boldSystemFontOfSize:15],
                                  NSForegroundColorAttributeName: [UIColor whiteColor] };
            NSString *s = num.stringValue;
            CGSize sz = [s sizeWithAttributes:at];
            [s drawAtPoint:CGPointMake(badge.origin.x + (24-sz.width)/2, badge.origin.y + (24-sz.height)/2) withAttributes:at];
        }
    }
    for (NSDictionary *h in self.highlights) {
        CGPoint p = [h[@"p"] CGPointValue];
        UIColor *col = h[@"color"] ?: [UIColor whiteColor];
        CGContextSetStrokeColorWithColor(ctx, col.CGColor);
        CGContextSetLineWidth(ctx, 4);
        CGContextSetShadowWithColor(ctx, CGSizeZero, 6, [UIColor blackColor].CGColor);
        CGRect ring = CGRectMake(p.x-22, p.y-26, 44, 52);
        UIBezierPath *bp = [UIBezierPath bezierPathWithRoundedRect:ring cornerRadius:8];
        [bp setLineWidth:4]; [col setStroke]; [bp stroke];
    }
}
@end

@interface RKPassWindow : UIWindow @end
@implementation RKPassWindow
- (UIView *)hitTest:(CGPoint)pt withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:pt withEvent:e];
    if (v == self || v == self.rootViewController.view) return nil;  // empty area -> game
    return v;                                                        // our controls
}
@end

@interface RKOverlay : NSObject
+ (void)ensure;
@end

static UIWindow *gWin = nil;
static RKDrawView *gDraw = nil;
static UILabel *gToast = nil;
static UIButton *gClose = nil;
static UIButton *gBtn = nil;
static UIButton *gAutoBtn = nil;
static NSTimer *gRefreshTimer = nil;
static NSTimer *gAutoTimer = nil;   // paces auto-place: one move per tick

// tile colour index -> UIColor / dark-text flag
static UIColor *rkTileColor(int c) {
    switch (c) {
        case 0: return [UIColor colorWithWhite:0.15 alpha:1];       // Black
        case 1: return [UIColor colorWithRed:0.15 green:0.45 blue:0.95 alpha:1]; // Blue
        case 2: return [UIColor colorWithRed:0.90 green:0.20 blue:0.20 alpha:1]; // Red
        case 3: return [UIColor colorWithRed:0.95 green:0.80 blue:0.10 alpha:1]; // Yellow
        default: return [UIColor grayColor];
    }
}
static int rkColorIndex(NSString *name) {
    if ([name isEqualToString:@"Black"]) return 0;
    if ([name isEqualToString:@"Blue"]) return 1;
    if ([name isEqualToString:@"Red"]) return 2;
    if ([name isEqualToString:@"Yellow"]) return 3;
    return -1;
}
// A tile chip: colour c (or -1 joker), number n (0=none). Returns a UILabel.
static UILabel *rkChip(int c, int n, BOOL joker) {
    UILabel *l = [[UILabel alloc] init];
    l.textAlignment = NSTextAlignmentCenter;
    l.font = [UIFont boldSystemFontOfSize:16];
    l.layer.cornerRadius = 6; l.layer.masksToBounds = YES;
    l.layer.borderWidth = 1; l.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.25].CGColor;
    if (joker) { l.text = @"★"; l.backgroundColor = [UIColor colorWithWhite:0.5 alpha:1]; l.textColor = [UIColor whiteColor]; }
    else {
        l.text = [NSString stringWithFormat:@"%d", n];
        l.backgroundColor = rkTileColor(c);
        l.textColor = (c == 3) ? [UIColor blackColor] : [UIColor whiteColor];  // yellow -> dark text
    }
    return l;
}

// find an unused tile in `pool` matching (c,n) [or joker]; prefer loc==preferLoc.
static NSMutableDictionary *rkTake(NSMutableArray *pool, int c, int n, BOOL joker, int preferLoc) {
    NSMutableDictionary *best = nil;
    for (NSMutableDictionary *t in pool) {
        if ([t[@"used"] boolValue]) continue;
        if (joker) { if (![t[@"j"] boolValue]) continue; }
        else { if ([t[@"j"] boolValue]) continue;
               if ([t[@"c"] intValue] != c || [t[@"n"] intValue] != n) continue; }
        if ([t[@"loc"] intValue] == preferLoc) { best = t; break; }
        if (!best) best = t;
    }
    if (best) best[@"used"] = @YES;
    return best;
}

@implementation RKOverlay
+ (void)toast:(NSString *)msg {
    gToast.text = msg; gToast.hidden = NO;
    [gToast.superview bringSubviewToFront:gToast];
}
+ (void)refresh {
    CGFloat H = gWin.bounds.size.height;
    CGFloat scale = gWin.screen.scale ?: [UIScreen mainScreen].scale;
    NSArray *tiles = rkGatherTiles(H, scale);
    [self logGrid:tiles];
    id res = rkComputeFromTiles(tiles);
    if (![res isKindOfClass:[NSDictionary class]]) { [self toast:[res description]]; return; }
    if (!tiles.count) { [self toast:@"타일 좌표를 못 읽음 — 매치 화면에서 다시"]; return; }
    int placed = [res[@"placed"] intValue];

    // Pool for set lines = ONLY board tiles + my rack tiles (exclude the stack/
    // draw pile and other players' racks so lines never point at them).
    NSMutableArray *pool = [NSMutableArray array];
    for (NSDictionary *t in tiles) {
        int loc = [t[@"loc"] intValue];
        if (loc == 2 || (loc == 1 && [t[@"mine"] boolValue])) [pool addObject:[t mutableCopy]];
    }

    // Lines: one per recommended set, connecting the current positions of its tiles.
    NSMutableArray *lines = [NSMutableArray array];
    int setNo = 0;
    for (NSString *raw in [res[@"sets"] componentsSeparatedByString:@"\n"]) {
        NSString *s = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (!s.length) continue;
        NSArray *parts = [s componentsSeparatedByString:@":"]; if (parts.count < 2) continue;
        NSArray *head = [parts[0] componentsSeparatedByString:@" "];
        NSArray *toks = [[parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]] componentsSeparatedByString:@" "];
        NSMutableArray *pts = [NSMutableArray array];
        UIColor *lc = [UIColor whiteColor];
        if ([head[0] isEqualToString:@"RUN"]) {
            int ci = rkColorIndex(head[1]); lc = rkTileColor(ci);
            int base = -1; for (int i=0;i<(int)toks.count;i++){ if(![toks[i] isEqualToString:@"J"]){ base=[toks[i] intValue]-i; break; } }
            for (int i=0;i<(int)toks.count;i++){ NSString*t=toks[i];
                NSMutableDictionary *td = [t isEqualToString:@"J"] ? rkTake(pool,0,0,YES,2) : rkTake(pool,ci,(base<0?[t intValue]:base+i),NO,2);
                if (td) [pts addObject:td[@"p"]]; }
        } else {
            int num = [head[1] intValue];
            for (NSString *t in toks) { if (![t length]) continue;
                NSMutableDictionary *td = [t isEqualToString:@"J"] ? rkTake(pool,0,0,YES,2) : rkTake(pool,rkColorIndex(t),num,NO,2);
                if (td) [pts addObject:td[@"p"]]; }
        }
        if (pts.count >= 2) [lines addObject:@{ @"pts": pts, @"color": lc, @"num": @(++setNo) }];
    }

    // Highlights: the rack tiles to play (bright cyan rings). Match on a fresh pass
    // over MINE rack tiles so highlights land on hand tiles even if used in a line.
    NSMutableArray *hi = [NSMutableArray array];
    NSMutableArray *rackPool = [NSMutableArray array];
    for (NSDictionary *t in tiles)
        if ([t[@"loc"] intValue]==1 && [t[@"mine"] boolValue]) [rackPool addObject:[t mutableCopy]];
    for (NSString *line in [res[@"place"] componentsSeparatedByString:@"\n"]) {
        NSRange colon = [line rangeOfString:@":"]; if (colon.location==NSNotFound) continue;
        int ci = rkColorIndex([line substringToIndex:colon.location]);
        for (NSString *tok in [[line substringFromIndex:colon.location+1] componentsSeparatedByString:@" "]) {
            if (!tok.length) continue;
            NSMutableDictionary *td = rkTake(rackPool, ci, tok.intValue, NO, 1);
            if (td) [hi addObject:@{ @"p": td[@"p"], @"color": [UIColor cyanColor] }];
        }
    }

    gDraw.lines = lines; gDraw.highlights = hi; gDraw.hidden = NO; [gDraw setNeedsDisplay];
    [self toast:[NSString stringWithFormat:@"%d장  ·  ①②③=만들 순서, 청록테=낼 타일  (✕ 닫기)", placed]];
    [gDraw.superview bringSubviewToFront:gDraw];
    [gToast.superview bringSubviewToFront:gToast];
    [gClose.superview bringSubviewToFront:gClose];
}
// One-shot: log every board/rack tile with its grid coords. This is how we learn
// the board coordinate convention for auto-place — read-only, on the tile-gather
// path that SOLVE already exercises (no extra hooks; hooking the move path and
// deep-dumping generic-heavy classes both destabilised the game when tried).
+ (void)logGrid:(NSArray *)tiles {
    static BOOL logged = NO;
    if (logged || !tiles.count) return;
    logged = YES;
    NSMutableString *b = [NSMutableString string], *r = [NSMutableString string];
    static const char *C[4] = { "K", "Bl", "R", "Y" };
    for (NSDictionary *t in tiles) {
        int loc = [t[@"loc"] intValue];
        if (loc != 2 && !(loc == 1 && [t[@"mine"] boolValue])) continue;
        NSString *nm = [t[@"j"] boolValue] ? @"J"
            : [NSString stringWithFormat:@"%s%d", C[MAX(0,MIN(3,[t[@"c"] intValue]))], [t[@"n"] intValue]];
        NSString *e = [NSString stringWithFormat:@"%@(id=%@ x=%@ y=%@) ",
                       nm, t[@"id"], t[@"gx"], t[@"gy"]];
        [(loc == 2 ? b : r) appendString:e];
    }
    LOG([NSString stringWithFormat:@"[grid] BOARD: %@", b]);
    LOG([NSString stringWithFormat:@"[grid] RACK : %@", r]);
}
// Resolve the solver's textual sets into the concrete tiles that will form them,
// reusing the same matcher the overlay used for its lines. Returns an array of
// arrays of tile dicts (board tiles preferred, so we move as few as possible).
+ (NSArray<NSArray *> *)resolveSets:(id)res tiles:(NSArray *)tiles {
    NSMutableArray *pool = [NSMutableArray array];
    for (NSDictionary *t in tiles) {
        int loc = [t[@"loc"] intValue];
        if (loc == 2 || (loc == 1 && [t[@"mine"] boolValue])) [pool addObject:[t mutableCopy]];
    }
    NSMutableArray *sets = [NSMutableArray array];
    for (NSString *raw in [res[@"sets"] componentsSeparatedByString:@"\n"]) {
        NSString *s = [raw stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (!s.length) continue;
        NSArray *parts = [s componentsSeparatedByString:@":"]; if (parts.count < 2) continue;
        NSArray *head = [parts[0] componentsSeparatedByString:@" "];
        NSArray *toks = [[parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]]
                          componentsSeparatedByString:@" "];
        NSMutableArray *set = [NSMutableArray array];
        if ([head[0] isEqualToString:@"RUN"]) {
            int ci = rkColorIndex(head[1]);
            int base = -1;
            for (int i = 0; i < (int)toks.count; i++)
                if (![toks[i] isEqualToString:@"J"]) { base = [toks[i] intValue] - i; break; }
            for (int i = 0; i < (int)toks.count; i++) {
                NSMutableDictionary *td = [toks[i] isEqualToString:@"J"]
                    ? rkTake(pool, 0, 0, YES, 2)
                    : rkTake(pool, ci, (base < 0 ? [toks[i] intValue] : base + i), NO, 2);
                if (td) [set addObject:td];
            }
        } else {
            int num = [head[1] intValue];
            for (NSString *t in toks) {
                if (!t.length) continue;
                NSMutableDictionary *td = [t isEqualToString:@"J"]
                    ? rkTake(pool, 0, 0, YES, 2)
                    : rkTake(pool, rkColorIndex(t), num, NO, 2);
                if (td) [set addObject:td];
            }
        }
        if (set.count >= 3) [sets addObject:set];
    }
    return sets;
}

// Auto-place: lay the solver's whole target configuration onto the board through
// the game's own move path, replacing the tangle of AR lines with actual moves.
//
// Layout starts *below* everything currently on the board. That keeps the target
// cells disjoint from the source cells, so no move can ever land on a tile that
// hasn't moved yet — with an in-place layout the ordering constraints become a
// real dependency graph. The turn is deliberately NOT confirmed: you review the
// result and press the game's own confirm (or undo).
+ (void)autoTap {
    ensureHooksMainThread();
    CGFloat H = gWin.bounds.size.height;
    CGFloat scale = gWin.screen.scale ?: [UIScreen mainScreen].scale;
    NSArray *tiles = rkGatherTiles(H, scale);
    if (!tiles.count) { [self toast:@"타일을 못 읽음 — 매치 화면에서"]; return; }
    id res = rkComputeFromTiles(tiles);
    if (![res isKindOfClass:[NSDictionary class]]) { [self toast:[res description]]; return; }

    int bx = 0, bw = 0, by = 0, bh = 0;
    if (!rkBoardBounds(tiles, &bx, &bw, &by, &bh)) { [self toast:@"보드 크기 못 읽음"]; return; }
    int maxY = by - 1;
    for (NSDictionary *t in tiles)
        if ([t[@"loc"] intValue] == 2) maxY = MAX(maxY, [t[@"gy"] intValue]);

    NSArray<NSArray *> *sets = [self resolveSets:res tiles:tiles];
    if (!sets.count) { [self toast:@"배치할 세트 없음"]; return; }

    // Full target layout: every set in the solved configuration gets a home,
    // packed left-to-right with one blank column between sets, wrapping rows
    // inside the real board rectangle. This is the whole point of AUTO — the
    // solution generally rearranges the table, which is exactly what is painful
    // to follow by hand from the overlay lines.
    // Lay every set out fresh, starting on the first row *below* everything
    // currently on the board, and let the board grow downward to fit.
    //
    // Two earlier layouts failed here. Packing into the existing rectangle cannot
    // work: 15 sets with a blank column between them need more than the 12x4 the
    // board starts at, so sets overflowed and were dropped. Pinning the sets that
    // were already correct made it worse — it fragmented the free space and left
    // no spare cell, so deadlocks could not be broken either. Starting below the
    // content keeps every destination clear of tiles that have not moved yet, so
    // no move can be blocked and no eviction is needed.
    // Play MY tiles into the sets the solver picked, and leave the board alone.
    //
    // Measured over many runs: rack -> board moves are accepted, board -> board
    // moves never are. Every attempt to relay the table (whole-set moves, growing
    // the board to make room, ordering by source safety) ended with every move
    // refused, while the runs that actually placed tiles were all rack -> board.
    // So do the part that works, which is also the part that matters: put down
    // what SOLVE says to put down.
    //
    // A set's tiles are in solver order, so one tile already on the board fixes
    // the alignment: if set[j] sits at column X, set[i] belongs at X - j + i.
    static char occ[64][64];
    memset(occ, 0, sizeof(occ));
    for (NSDictionary *t in tiles) {
        if ([t[@"loc"] intValue] != 2) continue;
        int cx = [t[@"gx"] intValue] - bx, cy = [t[@"gy"] intValue] - by;
        if (cx >= 0 && cx < 64 && cy >= 0 && cy < 64) occ[cy][cx] = 1;
    }

    NSMutableArray *targets = [NSMutableArray array];
    int noAnchor = 0, noSlot = 0;
    for (NSArray *set in sets) {
        int anchorIdx = -1, anchorX = 0, anchorY = 0;
        BOOL aligned = YES;
        NSMutableArray *mine = [NSMutableArray array];
        for (int i = 0; i < (int)set.count; i++) {
            NSDictionary *t = set[i];
            if ([t[@"loc"] intValue] == 2) {
                int gx = [t[@"gx"] intValue], gy = [t[@"gy"] intValue];
                if (anchorIdx < 0) { anchorIdx = i; anchorX = gx; anchorY = gy; }
                else if (gy != anchorY || gx - i != anchorX - anchorIdx) aligned = NO;
            } else if ([t[@"loc"] intValue] == 1 && [t[@"mine"] boolValue]) {
                [mine addObject:@{ @"t": t, @"i": @(i) }];
            }
        }
        if (!mine.count) continue;                       // nothing of mine in this set
        if (anchorIdx < 0) {                             // set is entirely from my rack
            int n = (int)set.count, sx = -1, sy = -1;
            for (int r = 0; r < bh && sx < 0; r++)
                for (int c = 0; c + n <= bw; c++) {
                    BOOL room = YES;
                    for (int k = -1; k <= n && room; k++) {
                        int cc = c + k;
                        if (cc < 0 || cc >= bw) continue;
                        if (occ[r][cc]) room = NO;
                    }
                    if (room) { sx = c; sy = r; break; }
                }
            if (sx < 0) { noSlot++; continue; }
            for (int k = 0; k < n; k++) occ[sy][sx + k] = 1;
            [targets addObject:@{ @"tiles": set, @"x": @(bx + sx), @"y": @(by + sy), @"attach": @0 }];
            continue;
        }
        (void)aligned;
        // Attach to the END of the block the anchor sits in, the way a player
        // does, instead of deriving a column from the tile's index in the solver's
        // list. That index only lines up for a run the board happens to store in
        // the same order; for a group (same number, mixed colours) the board order
        // is arbitrary, so the computed cell was off and the resulting board was
        // illegal — which is why even single-tile plays next to an existing set
        // were refused while plays into empty space worked.
        int leftX = anchorX, rightX = anchorX;
        while (leftX - 1 >= bx && occ[anchorY - by][leftX - 1 - bx]) leftX--;
        while (rightX + 1 < bx + bw && occ[anchorY - by][rightX + 1 - bx]) rightX++;

        BOOL isGroup = YES;                              // same number across the set?
        int firstNum = -1;
        for (NSDictionary *t in set) {
            if ([t[@"j"] boolValue]) continue;
            int n = [t[@"n"] intValue];
            if (firstNum < 0) firstNum = n; else if (n != firstNum) { isGroup = NO; break; }
        }
        // numbers currently at each end of the block
        int leftNum = -1, rightNum = -1;
        for (NSDictionary *t in tiles) {
            if ([t[@"loc"] intValue] != 2 || [t[@"gy"] intValue] != anchorY) continue;
            if ([t[@"gx"] intValue] == leftX)  leftNum  = [t[@"j"] boolValue] ? -1 : [t[@"n"] intValue];
            if ([t[@"gx"] intValue] == rightX) rightNum = [t[@"j"] boolValue] ? -1 : [t[@"n"] intValue];
        }

        for (NSDictionary *m in mine) {
            NSDictionary *t = m[@"t"];
            int myNum = [t[@"j"] boolValue] ? -1 : [t[@"n"] intValue];
            int tx = INT_MIN;
            if (isGroup || myNum < 0) {                  // group or joker: either free end
                if (rightX + 1 < bx + bw && !occ[anchorY - by][rightX + 1 - bx]) tx = ++rightX;
                else if (leftX - 1 >= bx && !occ[anchorY - by][leftX - 1 - bx]) tx = --leftX;
            } else {                                     // run: the end its value continues
                if (rightNum >= 0 && myNum == rightNum + 1 &&
                    rightX + 1 < bx + bw && !occ[anchorY - by][rightX + 1 - bx]) {
                    tx = ++rightX; rightNum = myNum;
                } else if (leftNum >= 0 && myNum == leftNum - 1 &&
                           leftX - 1 >= bx && !occ[anchorY - by][leftX - 1 - bx]) {
                    tx = --leftX; leftNum = myNum;
                }
            }
            if (tx == INT_MIN) { noSlot++; continue; }
            occ[anchorY - by][tx - bx] = 1;
            NSNumber *anchorId = nil;
            for (NSDictionary *st in set)
                if ([st[@"loc"] intValue] == 2) { anchorId = st[@"id"]; break; }
            [targets addObject:@{ @"tiles": @[ t ], @"x": @(tx), @"y": @(anchorY),
                                  @"attach": anchorId ?: @0 }];
        }
    }
    LOG([NSString stringWithFormat:@"[auto] board x0=%d w=%d y0=%d h=%d | plays=%lu needRearrange=%d noSlot=%d",
         bx, bw, by, bh, (unsigned long)targets.count, noAnchor, noSlot]);
    if (!targets.count) { [self toast:@"배치할 세트 없음"]; return; }

    // Execute adaptively instead of following a fixed order: a precomputed order
    // deadlocks as soon as a target cell still holds a tile that has not moved
    // yet. Each tick re-reads the live board, plays any move whose destination is
    // now free, and if nothing is playable, evicts one blocking tile to a spare
    // cell to break the cycle.
    [gAutoTimer invalidate];
    __block NSMutableArray *pend = [targets mutableCopy];
    __block NSMutableDictionary *attempts = [NSMutableDictionary dictionary];
    __block int ticks = 0, done = 0, stalled = 0, rotate = 0;
    __block NSUInteger lastLeft = NSUIntegerMax;
    gAutoTimer = [NSTimer scheduledTimerWithTimeInterval:0.3 repeats:YES block:^(NSTimer *tm) {
        CGFloat hh = gWin.bounds.size.height, sc = gWin.screen.scale ?: [UIScreen mainScreen].scale;
        NSArray *live = rkGatherTiles(hh, sc);
        int stallBudget = (int)pend.count * 2 + 6;   // give each pending move a few goes
        if (++ticks > 400 || !pend.count || !live.count || stalled >= stallBudget) {
            [tm invalidate]; gAutoTimer = nil;
            LOG([NSString stringWithFormat:@"[auto] finished done=%d left=%lu ticks=%d stalled=%d",
                 done, (unsigned long)pend.count, ticks, stalled]);
            [RKOverlay toast:stalled >= 5
                ? @"자동배치 중단 — 수가 거부됨(내 턴이 아니거나 배치 불가)"
                : [NSString stringWithFormat:@"자동배치 종료 — %d수 (남음 %lu)",
                   done, (unsigned long)pend.count]];
            return;
        }
        // Use the container's rendered position (cx/cy/cloc), not the Card's —
        // see rkGatherTiles: the Card copy can lag, which previously made every
        // move look unfinished and repeat forever.
        NSMutableDictionary *at = [NSMutableDictionary dictionary];   // "x,y" -> cardID
        NSMutableDictionary *posOf = [NSMutableDictionary dictionary];// cardID -> tile
        for (NSDictionary *t in live) {
            posOf[t[@"id"]] = t;
            if ([t[@"loc"] intValue] == 2)
                at[[NSString stringWithFormat:@"%@,%@", t[@"gx"], t[@"gy"]]] = t[@"id"];
        }
        // A set is done when every one of its tiles sits on its target run.
        for (NSInteger i = pend.count - 1; i >= 0; i--) {
            NSDictionary *m = pend[i];
            // Done once every tile of the move is on the board. Requiring the
            // exact planned cell kept re-issuing moves for tiles the game had
            // already placed a column over, which is what scattered them.
            NSArray *tl = m[@"tiles"];
            BOOL all = YES;
            for (NSUInteger k = 0; k < tl.count && all; k++) {
                NSDictionary *cur = posOf[((NSDictionary *)tl[k])[@"id"]];
                all = cur && [cur[@"loc"] intValue] == 2;
            }
            if (all) [pend removeObjectAtIndex:i];
        }
        // If the pending count stops falling, the game is refusing our moves —
        // typically because the turn ended. Give up rather than spin.
        if (pend.count == lastLeft) stalled++; else { stalled = 0; lastLeft = pend.count; }
        if (!pend.count) return;                                       // next tick reports done
        // Group the board into its current runs (maximal contiguous tiles in a
        // row) so we can reason about what a move takes *away*, not just where it
        // lands. Taking the middle out of a run leaves a fragment, the board is
        // momentarily illegal and the game refuses the move — that is why AUTO
        // always stalled partway with sets it could never place.
        NSMutableDictionary *runOf = [NSMutableDictionary dictionary];   // cardID -> run id
        NSMutableDictionary *runIdx = [NSMutableDictionary dictionary];  // cardID -> index in run
        NSMutableDictionary *runLen = [NSMutableDictionary dictionary];  // run id  -> length
        {
            NSMutableDictionary *rows = [NSMutableDictionary dictionary];
            for (NSDictionary *t in live) {
                if ([t[@"loc"] intValue] != 2) continue;
                NSMutableArray *r = rows[t[@"gy"]];
                if (!r) { r = [NSMutableArray array]; rows[t[@"gy"]] = r; }
                [r addObject:t];
            }
            int rid = 0;
            for (NSNumber *y in rows) {
                NSArray *r = [rows[y] sortedArrayUsingComparator:^NSComparisonResult(id a, id b) {
                    return [a[@"gx"] compare:b[@"gx"]]; }];
                NSMutableArray *cur = [NSMutableArray array];
                int prev = INT_MIN;
                for (NSDictionary *t in r) {
                    int x = [t[@"gx"] intValue];
                    if (prev != INT_MIN && x != prev + 1) {
                        rid++; runLen[@(rid)] = @(cur.count);
                        for (NSUInteger k = 0; k < cur.count; k++) {
                            runOf[cur[k]] = @(rid); runIdx[cur[k]] = @(k);
                        }
                        cur = [NSMutableArray array];
                    }
                    [cur addObject:t[@"id"]];
                    prev = x;
                }
                if (cur.count) {
                    rid++; runLen[@(rid)] = @(cur.count);
                    for (NSUInteger k = 0; k < cur.count; k++) {
                        runOf[cur[k]] = @(rid); runIdx[cur[k]] = @(k);
                    }
                }
            }
        }

        // Playable = destination clear AND every source run is either fully
        // consumed or only loses tiles from one of its ends (remainder >= 3).
        NSDictionary *chosen = nil;
        NSMutableArray *playable = [NSMutableArray array];
        for (NSDictionary *m in pend) {
            NSArray *tl = m[@"tiles"];
            NSMutableArray *ids = [NSMutableArray array];
            for (NSDictionary *t in tl) [ids addObject:t[@"id"]];
            int sx = [m[@"x"] intValue], sy = [m[@"y"] intValue];
            BOOL ok = YES;
            for (NSUInteger k = 0; k < tl.count && ok; k++) {
                NSNumber *occupant = at[[NSString stringWithFormat:@"%d,%d", sx + (int)k, sy]];
                if (occupant && ![ids containsObject:occupant]) ok = NO;
            }
            if (ok) {
                NSMutableDictionary *takenBy = [NSMutableDictionary dictionary];  // run -> indices
                for (NSNumber *cid in ids) {
                    NSNumber *r = runOf[cid];
                    if (!r) continue;                       // from my rack: always free
                    NSMutableArray *v = takenBy[r];
                    if (!v) { v = [NSMutableArray array]; takenBy[r] = v; }
                    [v addObject:runIdx[cid]];
                }
                for (NSNumber *r in takenBy) {
                    NSArray *idxs = [takenBy[r] sortedArrayUsingSelector:@selector(compare:)];
                    int len = [runLen[r] intValue], take = (int)idxs.count;
                    if (take == len) continue;              // run fully consumed: fine
                    int lo = [idxs.firstObject intValue], hi = [idxs.lastObject intValue];
                    BOOL contiguous = (hi - lo + 1) == take;
                    BOOL atEnd = (lo == 0) || (hi == len - 1);
                    if (!contiguous || !atEnd || (len - take) < 3) { ok = NO; break; }
                }
            }
            if (ok) { [playable addObject:m]; }
        }
        // Rotate through the playable moves instead of retrying whichever comes
        // first. A refused move often becomes legal once another one lands, so
        // hammering the same target four times and then abandoning the whole plan
        // (what happened before) throws away moves that were still achievable.
        if (playable.count) {
            chosen = playable[rotate % playable.count];
            rotate++;
        }
        if (chosen) {
            NSArray *ctiles = chosen[@"tiles"];
            int tx = [chosen[@"x"] intValue], ty = [chosen[@"y"] intValue];
            // Give up on a move the game keeps refusing rather than reissuing it
            // forever (observed: the same card fired 15+ times, never landing).
            NSString *key = [NSString stringWithFormat:@"%d,%d", tx, ty];
            int tries = [attempts[key] intValue] + 1;
            attempts[key] = @(tries);
            if (tries > 12) {                      // truly stuck: stop reserving its slot
                LOG([NSString stringWithFormat:@"[auto] dropping set at (%d,%d) after %d tries", tx, ty, tries]);
                [pend removeObject:chosen];
                return;
            }
            // Recording a manual drag proved board->board moves are legal and
            // that no intermediate pick-up state exists, so the payload is what
            // differs. MoveMakingSeat is the one field guessed outright (always
            // 0) — cycle it across retries and see which, if any, is accepted.
            // Say *why* a move is not taking. Without this the log only showed
            // "fired" over and over, so it was impossible to tell a wrongly
            // computed cell from a placement the game considers illegal.
            if (tries >= 2) {
                NSMutableString *around = [NSMutableString string];
                for (int c = tx - 2; c <= tx + (int)ctiles.count + 1; c++) {
                    NSString *what = @".";
                    for (NSDictionary *t in live)
                        if ([t[@"loc"] intValue] == 2 && [t[@"gx"] intValue] == c &&
                            [t[@"gy"] intValue] == ty) {
                            what = [t[@"j"] boolValue] ? @"J"
                                 : [NSString stringWithFormat:@"%@:%@", t[@"c"], t[@"n"]];
                            break;
                        }
                    [around appendFormat:@"%d=%@ ", c, what];
                }
                NSMutableString *what = [NSMutableString string];
                for (NSDictionary *t in ctiles)
                    [what appendFormat:@"%@%@:%@ ", [t[@"loc"] intValue] == 1 ? @"rack " : @"board ",
                     t[@"c"], t[@"n"]];
                LOG([NSString stringWithFormat:@"[auto] refused: placing [%@] at (%d,%d); row: %@",
                     what, tx, ty, around]);
            }
            void *md = rkBuildMove(ctiles, tx, ty, [chosen[@"attach"] intValue]);
            BOOL fired = md ? rkApplyMove(md) : NO;
            if (fired) done++;
            LOG([NSString stringWithFormat:@"[auto] set(%lu tiles) -> (%d,%d) fired=%d try=%d left=%lu",
                 (unsigned long)ctiles.count, tx, ty, fired, tries, (unsigned long)pend.count]);
        } else {
            // Deadlock: evict whatever sits on the first pending target.
            NSDictionary *m = pend[0];
            NSNumber *blocker = at[[NSString stringWithFormat:@"%@,%@", m[@"x"], m[@"y"]]];
            NSDictionary *blockTile = nil;
            if (blocker) for (NSDictionary *t in live) if ([t[@"id"] isEqual:blocker]) { blockTile = t; break; }
            int fx = -1, fy = -1;
            for (int r = 0; r < bh && fx < 0; r++)
                for (int c = 0; c < bw; c++)
                    if (!at[[NSString stringWithFormat:@"%d,%d", bx + c, by + r]]) { fx = bx + c; fy = by + r; break; }
            if (blockTile && fx >= 0) {
                void *md = rkBuildMove(@[ blockTile ], fx, fy, 0);
                BOOL fired = md ? rkApplyMove(md) : NO;
                LOG([NSString stringWithFormat:@"[auto] evict card=%@ -> (%d,%d) fired=%d",
                     blocker, fx, fy, fired]);
            } else {
                LOG(@"[auto] stuck: no free cell to evict into");
                [tm invalidate]; gAutoTimer = nil;
                [RKOverlay toast:@"자동배치 막힘 — 보드에 빈 칸 없음"];
                return;
            }
        }
        rkSyncVisuals();          // model moved; drag the 3D tiles to match
        [RKOverlay toast:[NSString stringWithFormat:@"배치 중 — 남음 %lu", (unsigned long)pend.count]];
    }];
}
+ (void)tap {
    LOG(@"[overlay] SOLVE tapped");
    gClose.hidden = NO; gBtn.hidden = YES;
    [self refresh];
    // live update: re-solve + redraw so highlights/lines follow hand/board changes
    [gRefreshTimer invalidate];
    gRefreshTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t){
        if (gDraw.hidden) { [t invalidate]; return; }
        [RKOverlay refresh];
    }];
}
+ (void)hide { [gRefreshTimer invalidate]; gRefreshTimer = nil;
               gDraw.hidden = YES; gToast.hidden = YES; gClose.hidden = YES; gBtn.hidden = NO; }
+ (void)ensure {
    if (gWin) return;
    NSArray *scenes = [UIApplication sharedApplication].connectedScenes.allObjects;
    UIWindowScene *scene = nil;
    for (UIScene *s in scenes)
        if ([s isKindOfClass:[UIWindowScene class]] &&
            s.activationState == UISceneActivationStateForegroundActive) { scene = (UIWindowScene *)s; break; }
    if (!scene)   // fall back to any window scene, then to keyWindow's scene
        for (UIScene *s in scenes)
            if ([s isKindOfClass:[UIWindowScene class]]) { scene = (UIWindowScene *)s; break; }
    static int logged = 0;
    if (logged < 8) { logged++;
        LOG([NSString stringWithFormat:@"[overlay] scenes=%lu picked=%@ state=%ld",
             (unsigned long)scenes.count, scene ? @"yes" : @"NO",
             scene ? (long)scene.activationState : -1]); }
    if (!scene) return;   // try again later
    RKPassWindow *win = [[RKPassWindow alloc] initWithWindowScene:scene];
    win.frame = scene.coordinateSpace.bounds;
    win.windowLevel = (UIWindowLevel)1000000;   // above Unity's window
    win.backgroundColor = [UIColor clearColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor clearColor];
    win.rootViewController = vc;
    win.hidden = NO;
    gWin = win;
    UIView *root = vc.view;
    CGRect b = win.bounds;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeSystem];
    btn.frame = CGRectMake(b.size.width - 92, 60, 78, 40);
    btn.backgroundColor = [[UIColor systemGreenColor] colorWithAlphaComponent:0.9];
    [btn setTitle:@"🧮 SOLVE" forState:UIControlStateNormal];
    [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    btn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    btn.layer.cornerRadius = 8;
    btn.layer.zPosition = 100000;
    [btn addTarget:self action:@selector(tap) forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(drag:)];
    [btn addGestureRecognizer:pan];
    [root addSubview:btn];
    [root bringSubviewToFront:btn];
    gBtn = btn;

    UIButton *ab = [UIButton buttonWithType:UIButtonTypeSystem];
    ab.frame = CGRectMake(b.size.width - 92, 106, 78, 36);
    ab.backgroundColor = [[UIColor systemOrangeColor] colorWithAlphaComponent:0.9];
    [ab setTitle:@"⚙︎ AUTO" forState:UIControlStateNormal];
    [ab setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    ab.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    ab.layer.cornerRadius = 8;
    ab.layer.zPosition = 100000;
    [ab addTarget:self action:@selector(autoTap) forControlEvents:UIControlEventTouchUpInside];
    [root addSubview:ab];
    gAutoBtn = ab;



    // Full-screen transparent draw layer for AR highlights/lines (touch passes through).
    RKDrawView *dv = [[RKDrawView alloc] initWithFrame:b];
    dv.backgroundColor = [UIColor clearColor];
    dv.opaque = NO;
    dv.userInteractionEnabled = NO;
    dv.hidden = YES;
    [root addSubview:dv];
    gDraw = dv;

    // Small toast label at top-centre for the summary line.
    UILabel *toast = [[UILabel alloc] initWithFrame:CGRectMake(60, 8, b.size.width - 160, 30)];
    toast.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.75];
    toast.textColor = [UIColor whiteColor];
    toast.font = [UIFont boldSystemFontOfSize:13];
    toast.textAlignment = NSTextAlignmentCenter;
    toast.layer.cornerRadius = 8; toast.layer.masksToBounds = YES;
    toast.numberOfLines = 1; toast.adjustsFontSizeToFitWidth = YES;
    toast.hidden = YES;
    [root addSubview:toast];
    gToast = toast;

    // Close (✕) button top-right corner (replaces SOLVE while a result is shown).
    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(b.size.width - 52, 44, 40, 40);
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    close.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.6];
    close.titleLabel.font = [UIFont boldSystemFontOfSize:22];
    close.layer.cornerRadius = 20;
    close.layer.zPosition = 100002;
    close.hidden = YES;
    [close addTarget:self action:@selector(hide) forControlEvents:UIControlEventTouchUpInside];
    [root addSubview:close];
    gClose = close;
    // keep the button on top even if the game adds views later
    [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *tm){
        if (!btn.hidden && btn.superview) [btn.superview bringSubviewToFront:btn];
        // Arm the capture/observation hooks here rather than from the AUTO button,
        // so they are in place for moves the player makes by hand too.
        ensureHooksMainThread();
    }];
    LOG([NSString stringWithFormat:@"[overlay] attached to host window bounds=%@", NSStringFromCGRect(b)]);
}
+ (void)drag:(UIPanGestureRecognizer *)g {
    CGPoint t = [g translationInView:g.view.superview];
    g.view.center = CGPointMake(g.view.center.x + t.x, g.view.center.y + t.y);
    [g setTranslation:CGPointZero inView:g.view.superview];
}
@end

static void *overlayEntry(void *unused) {
    // Retry until a foreground scene exists, then build the overlay on main.
    for (int i = 0; i < 1200; i++) {
        __block BOOL done = NO;
        dispatch_sync(dispatch_get_main_queue(), ^{ [RKOverlay ensure]; done = (gWin != nil); });
        if (done) return NULL;
        usleep(250000);
    }
    return NULL;
}

%ctor {
    @autoreleasepool {
        gLog = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/rk_recon.log"];
        gCardsLog = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/rk_cards.log"];
        [[NSFileManager defaultManager] createDirectoryAtPath:[gLog stringByDeletingLastPathComponent]
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        [[NSString stringWithFormat:@"[rkreader] log=%@\n", gLog]
            writeToFile:gLog atomically:NO encoding:NSUTF8StringEncoding error:nil];
        LOG(@"[rkreader] loaded, waiting for il2cpp…");
        %init(VCDiag);
        pthread_t th; pthread_create(&th, NULL, reconEntry, NULL); pthread_detach(th);
        pthread_t th2; pthread_create(&th2, NULL, adEntry, NULL); pthread_detach(th2);
        pthread_t th3; pthread_create(&th3, NULL, overlayEntry, NULL); pthread_detach(th3);
    }
}
