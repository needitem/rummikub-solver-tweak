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
static bool (*orig_creategrid)(void*, void*, void*);
static bool hook_creategrid(void *selfManip, void *gameData, void *method) {
    if (gameData) gGameData = gameData;
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
%group VCDiag
%hook UIViewController
- (void)presentViewController:(UIViewController *)vc animated:(BOOL)a completion:(void(^)(void))c {
    NSString *cn = vc ? NSStringFromClass([vc class]) : @"nil";
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
        [out addObject:@{ @"c": @(color), @"n": @(num), @"j": @(joker),
                          @"loc": @(loc), @"mine": @(!(os.length>=3 && [os hasPrefix:@"AI_"])),
                          @"p": [NSValue valueWithCGPoint:CGPointMake(x, y)] }];
    }
    return out;
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
static NSTimer *gRefreshTimer = nil;

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
