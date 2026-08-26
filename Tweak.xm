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

    // Field name + offset + static flag only. We deliberately do NOT resolve
    // field TYPE names — il2cpp_type_get_name crashes on some generic/complex
    // field types, and offsets are what we need to read values later.
    void *iter = NULL, *field; int guard = 0;
    while ((field = f_class_get_fields(klass, &iter)) && guard++ < 256) {
        const char *fn = f_field_get_name(field);
        size_t off = f_field_get_offset ? f_field_get_offset(field) : 0;
        int flags = f_field_get_flags ? f_field_get_flags(field) : 0;
        BOOL isStatic = (flags & 0x10) != 0;   // FIELD_ATTRIBUTE_STATIC

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
// ================= Card reader =================
//
// RmkbGameData layout (from recon):
//   0xa0 Cards            : Card[]           (all 106 tiles)
//   0xb0 BoardCards       : List<Card>
//   0xc0 CardsByPlayerID  : Dictionary<string,List<Card>>
// Card:  0x10 OwnerPlayerID:String  0x1c Location:enum(0 Stack,1 Player,2 Board)  0x38 Value:CardValue*
// CardValue: 0x10 Color:int  0x14 NumericValue:int  0x18 IsJoker:bool

static void *gGameData = NULL;                    // captured live RmkbGameData*

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

// Capture the RmkbMovesData of every move the game validates, so a manual drag
// shows the exact payload a legal board->board rearrangement carries (tagged MAN)
// next to ours (SYN).
//
// The obvious interception point, FireMoveMadeEvent, cannot be hooked: when the
// game calls it at the end of a real drag, execution lands on the trampoline page
// and dies (SIGBUS/KERN_PROTECTION_FAILURE at an address in no image). Hook the
// validator instead — CheckMoveWithinBoardRange sees the same payload and returns
// a plain bool, so there is no value-type return to corrupt either.


static NSString *decodeString(void *s) {
    if (!s) return @"";
    int len = *(int*)((char*)s + 0x10);
    if (len < 0 || len > 8192) return @"";
    uint16_t *c = (uint16_t*)((char*)s + 0x14);
    return [NSString stringWithCharacters:c length:(NSUInteger)len];
}

static void installCaptureHook(const void *img) {
    static BOOL installed = NO;
    if (installed) return;
    if (!f_MSHookFunction || !f_class_from_name || !f_class_get_method_from_name) {
         return;
    }
    void *k = f_class_from_name(img, "", "RmkbGameData");
    if (!k) { return; }
    void *m = f_class_get_method_from_name(k, "SetRackPositionsFromLocalData", 2);
    if (!m) { return; }
    void *fp = *(void**)m;                     // MethodInfo.methodPointer (offset 0)
    if (fp) { f_MSHookFunction(fp, (void*)hook_setrack, (void**)&orig_setrack);
               }
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
                              } }
    }
    // Do NOT hook FireMoveMadeEvent: being void/one-arg is not enough. When the
    // game calls it at the end of a real drag, control lands on the trampoline
    // page and dies (SIGBUS / KERN_PROTECTION_FAILURE executing at an address in
    // no image, Unity Main Thread). Calling it ourselves is fine — it is only
    // hooking it that breaks.
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

static void ensureHooksMainThread(void);   // defined below

// Hook installation used to run on this background thread, walking il2cpp as soon
// as the symbols resolved. On some launches the runtime is still building its
// tables at that moment and il2cpp_domain_get()/domain_get_assemblies() fault
// (EXC_BAD_ACCESS near null), killing the game seconds after launch — which is
// what happened when a manual rearrange was attempted right after installing.
// Touch il2cpp only from the main thread, well after the app is up and running,
// and retry until it takes.
static void reconThread(void) {

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        __block int tries = 0;
        [NSTimer scheduledTimerWithTimeInterval:3.0 repeats:YES block:^(NSTimer *tm) {
            tries++;
            // Only reach into the runtime while the app is actually foreground-active;
            // that is the cheapest proxy we have for "Unity finished starting".
            if ([UIApplication sharedApplication].applicationState != UIApplicationStateActive) {
                if (tries > 200) [tm invalidate];
                return;
            }
            ensureHooksMainThread();
            if (gAsmImg || tries > 200) {
                [tm invalidate];

            }
        }];
    });
}

static void *reconEntry(void *unused) { @autoreleasepool { reconThread(); } return NULL; }

// ================= Ad suppression (AppLovin MAX) =================
// Blocks fullscreen interstitials, app-open ads and banners by no-op'ing the
// SDK's public show/load entry points. Rewarded ads are intentionally left
// intact (blocking them would also withhold the in-game reward they grant).

%group ALHooks
%hook MAInterstitialAd
- (void)showAd { }
- (void)showAdForPlacement:(id)p { }
- (void)showAdForPlacement:(id)p customData:(id)c { }
- (void)showAdForPlacement:(id)p customData:(id)c viewController:(id)vc { }
%end
%hook MAAppOpenAd
- (void)showAd { }
- (void)showAdForPlacement:(id)p { }
- (void)showAdForPlacement:(id)p customData:(id)c { }
- (void)showAdForPlacement:(id)p customData:(id)c viewController:(id)vc { }
%end
%hook MAAdView
- (void)loadAd { }
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

        if (c) c();                       // let the caller's completion run
        return;
    }

    %orig(vc, a, c);
}
%end
%end  // group VCDiag

static void adWaitAndInit(void) {
    for (int i = 0; i < 900; i++) { // up to ~90s
        if (NSClassFromString(@"MAInterstitialAd") || NSClassFromString(@"MAAdView")) {
            %init(ALHooks);

            return;
        }
        usleep(100000);
    }

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
        if (loc == 2) { // Board
            if (joker) jb++;
            else if (color >= 0 && color < NCOL && num >= 1 && num <= NNUM) board[color][num]++;
        } else if (loc == 1 && mine) { // my rack
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
// Opt-in diagnostics: writes only when a file named rk_capture sits next to the
// log, so normal play stays silent and a noisy build cannot spoil a game.
static void RKLOG(NSString *fmt, ...) NS_FORMAT_FUNCTION(1,2);
static void RKLOG(NSString *fmt, ...) {
    static int on = -1;
    static NSString *path = nil;
    if (on < 0) {
        NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
        on = [[NSFileManager defaultManager] fileExistsAtPath:
              [dir stringByAppendingPathComponent:@"rk_capture"]] ? 1 : 0;
        path = [dir stringByAppendingPathComponent:@"rk_recon.log"];
    }
    if (!on) return;
    va_list ap; va_start(ap, fmt);
    NSString *line = [[[NSString alloc] initWithFormat:fmt arguments:ap]
                      stringByAppendingString:@"\n"];
    va_end(ap);
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) { [line writeToFile:path atomically:NO encoding:NSUTF8StringEncoding error:nil]; return; }
    @try { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; }
    @finally { [fh closeFile]; }
}

static BOOL rkApplyMove(void *md);      // defined below

// Ask the game to sort my rack. RmkbMoveDetails is part of the move payload
// (MoveTiles=0, ArrangeByColor=1, ArrangeByValue=2), so a sort is one move —
// and the game lays sequences out with a blank after each
// (addSpaceAfterSequences), which is exactly the shape a block lift wants.
// Sorting first turns "three separate tiles" into "one run already side by
// side", so a set that cost three moves to place now costs one.
static BOOL rkArrangeRack(int mode) {
    if (!f_object_new || !f_class_from_name || !f_class_get_method_from_name) return NO;
    void *cls = f_class_from_name(gAsmImg, "", "RmkbMovesData");
    if (!cls) return NO;
    void *md = f_object_new(cls);
    if (!md) return NO;
    void *ctor = f_class_get_method_from_name(cls, ".ctor", 0);
    if (ctor) { void *exc = NULL; f_runtime_invoke(ctor, md, NULL, &exc); if (exc) return NO; }
    *(int*)((char*)md + 0x18) = mode;      // MoveDetails: 1 = by colour, 2 = by value
    *(int*)((char*)md + 0x1c) = 1;         // TargetLocation = Player (the rack)
    *(int*)((char*)md + 0x28) = -1;        // PreferredCardToAttatchTo: none
    return rkApplyMove(md);
}

static void *rkBuildMove(NSArray *tilesOfSet, int targetX, int targetY, int attachTo) {
    if (!tilesOfSet.count) return NULL;
    if (!f_object_new || !f_object_get_class || !f_class_from_name ||
        !f_class_get_method_from_name || !f_runtime_invoke) return NULL;
    void *cls = f_class_from_name(gAsmImg, "", "RmkbMovesData");
    if (!cls) { return NULL; }
    void *md = f_object_new(cls);
    if (!md) { return NULL; }
    void *ctor = f_class_get_method_from_name(cls, ".ctor", 0);
    if (ctor) { void *exc = NULL; f_runtime_invoke(ctor, md, NULL, &exc);
                if (exc) { return NULL; } }
    void *lst = *(void**)((char*)md + 0x30);
    if (!lst) { return NULL; }
    void *lcls = f_object_get_class(lst);
    void *mAdd = lcls ? f_class_get_method_from_name(lcls, "Add", 1) : NULL;
    if (!mAdd) { return NULL; }
    for (NSDictionary *t in tilesOfSet) {
        int idv = [t[@"id"] intValue];
        void *args[1] = { &idv }; void *exc = NULL;
        f_runtime_invoke(mAdd, lst, args, &exc);
        if (exc) { return NULL; }
        void *card = (void *)(uintptr_t)[t[@"cptr"] unsignedLongLongValue];
        if (card) *(int*)((char*)card + 0x34) = 2;      // Card.MoveType, as the game sets
    }
    *(int*)((char*)md + 0x1c) = 2;                       // TargetLocation = Board
    *(int*)((char*)md + 0x20) = targetX;
    *(int*)((char*)md + 0x24) = targetY;
    // PreferredCardToAttatchTo is -1 for "none" — captured from real drags, which
    // always carry -1 (typ=0 seat=0 det=0 loc=2 x=.. y=.. attach=-1 cards=[id]).
    // Card ids start at 0, so the old "leave it at 0 / pass the anchor id" both
    // named a real card to attach to and sent the tile somewhere else; that, not
    // board legality, is why every board->board move came back refused.
    (void)attachTo;
    *(int*)((char*)md + 0x28) = -1;
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
    if (!gView) { return NO; }
    void *vcls = f_class_from_name(gAsmImg, "", "RmkbGameView3D");
    void *mFire = vcls ? f_class_get_method_from_name(vcls, "FireMoveMadeEvent", 1) : NULL;
    if (!mFire) { return NO; }
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
    if (!mWorld || !mGetPos || !mSetPos) { return; }

    int bOrgX = 100, bOrgY = 100;                         // board origin (RmkbGameData)
    if (gGameData) {
        bOrgX = *(int*)((char*)gGameData + 0x90);
        bOrgY = *(int*)((char*)gGameData + 0x98);
    }
    void *arr = *(void**)((char*)gView + 0x140);          // Tiles : TileContainer[]
    size_t cnt = (arr && f_array_length) ? f_array_length(arr) : 0;
    if (!cnt) { return; }
    void **elems = (void**)((char*)arr + 0x20);

    BOOL calibrated = NO;
    int moved = 0;
    for (size_t pass = 0; pass < 2; pass++) { // pass 0 = calibrate, 1 = apply
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
                if (d < 0.05f) { // this tile is already where the formula says
                    calibrated = YES;

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

            return;
        }
    }

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

            return YES;
        }
    }
    // No tile-extent fallback: stray tiles outside the play area dragged the
    // inferred origin to x=99 and every queued target landed off-board, so the
    // game refused the lot. Better to refuse to run than to aim at nothing.

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

    }
    return res;
}

// ================= On-screen overlay (button + result panel) =================
// A dedicated top-level window that passes touches through EXCEPT on its own
// controls, so the game keeps working while our button/panel stay visible+tappable.
// A transparent view that draws highlight rings on the tiles to play
// connecting each recommended set. Non-interactive (touches pass through).
@interface RKDrawView : UIView
@property (nonatomic, strong) NSArray *highlights;  // dicts {p:NSValue, color:UIColor}
@end
@implementation RKDrawView
- (void)drawRect:(CGRect)r {
    CGContextRef ctx = UIGraphicsGetCurrentContext();
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
static UIButton *gBtn = nil;
static NSTimer *gRefreshTimer = nil;
static UIButton *gAutoBtn = nil;
static NSTimer *gAutoTimer = nil;   // paces auto-place: one move per tick

// Seconds per placed tile — hold the AUTO button to change it.
//
// This is a hand reaching across a board, not a script: below about half a
// second the tiles snap into place faster than anyone could drag them. The
// timer itself runs at a fixed poll and acts only once the interval has
// elapsed, so a run in flight picks up a new setting on its next tile instead
// of having to be restarted.
static const NSTimeInterval kAutoPoll = 0.05;
static const NSTimeInterval kAutoTickMin = 0.1, kAutoTickMax = 1.0;
static NSString * const kAutoTickKey = @"RKAutoTick";
static NSTimeInterval gAutoTick = 0.6;
static UIView *gSpeedPanel = nil;
static UILabel *gSpeedLabel = nil;

static void rkLoadAutoTick(void) {
    double v = [[NSUserDefaults standardUserDefaults] doubleForKey:kAutoTickKey];
    if (v >= kAutoTickMin && v <= kAutoTickMax) gAutoTick = v;
}

// tile colour index -> UIColor / dark-text flag
static int rkColorIndex(NSString *name) {
    if ([name isEqualToString:@"Black"]) return 0;
    if ([name isEqualToString:@"Blue"]) return 1;
    if ([name isEqualToString:@"Red"]) return 2;
    if ([name isEqualToString:@"Yellow"]) return 3;
    return -1;
}
// A tile chip: colour c (or -1 joker), number n (0=none). Returns a UILabel.
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

// A floating control: tap to act, drag to move it out of the way.
static UIButton *rkMakeButton(NSString *title, UIColor *tint, CGRect frame,
                              id target, SEL action) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.frame = frame;
    b.backgroundColor = [tint colorWithAlphaComponent:0.9];
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    b.layer.cornerRadius = 8;
    b.layer.zPosition = 100000;
    [b addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    [b addGestureRecognizer:[[UIPanGestureRecognizer alloc]
        initWithTarget:target action:NSSelectorFromString(@"drag:")]];
    return b;
}

@implementation RKOverlay
+ (void)toast:(NSString *)msg {
    gToast.text = msg; gToast.hidden = NO;
    [gToast.superview bringSubviewToFront:gToast];
}
// Ring the rack tiles the solver can place this turn, and nothing else.
//
// The earlier version also drew a line through every recommended set. On a real
// board that is a dozen crossing lines describing groupings you cannot act on
// directly anyway — the only thing worth knowing at a glance is which tiles in
// your hand can go out. AUTO handles the rest.
+ (void)refresh {
    CGFloat H = gWin.bounds.size.height;
    CGFloat scale = gWin.screen.scale ?: [UIScreen mainScreen].scale;
    NSArray *tiles = rkGatherTiles(H, scale);
    if (!tiles.count) { [self toast:@"타일 좌표를 못 읽음 — 매치 화면에서"]; return; }
    id res = rkComputeFromTiles(tiles);
    if (![res isKindOfClass:[NSDictionary class]]) { [self toast:[res description]]; return; }

    // Match against a fresh pass over MY rack only, so a tile is ringed where it
    // sits in the hand rather than wherever else that face value appears.
    NSMutableArray *rackPool = [NSMutableArray array];
    for (NSDictionary *t in tiles)
        if ([t[@"loc"] intValue] == 1 && [t[@"mine"] boolValue])
            [rackPool addObject:[t mutableCopy]];

    NSMutableArray *hi = [NSMutableArray array];
    for (NSString *line in [res[@"place"] componentsSeparatedByString:@"\n"]) {
        NSRange colon = [line rangeOfString:@":"]; if (colon.location == NSNotFound) continue;
        int ci = rkColorIndex([line substringToIndex:colon.location]);
        for (NSString *tok in [[line substringFromIndex:colon.location+1] componentsSeparatedByString:@" "]) {
            if (!tok.length) continue;
            NSMutableDictionary *td = rkTake(rackPool, ci, tok.intValue, NO, 1);
            if (td) [hi addObject:@{ @"p": td[@"p"], @"color": [UIColor cyanColor] }];
        }
    }

    gDraw.highlights = hi; gDraw.hidden = NO; [gDraw setNeedsDisplay];
    [self toast:hi.count ? [NSString stringWithFormat:@"낼 수 있는 타일 %lu장", (unsigned long)hi.count]
                         : @"지금 낼 수 있는 타일 없음"];
    [gDraw.superview bringSubviewToFront:gDraw];
    [gToast.superview bringSubviewToFront:gToast];
}

// Toggle the hand overlay. While on, it re-solves twice a second so the rings
// follow the hand and board as they change.
+ (void)toggle {
    if (gRefreshTimer) {
        [gRefreshTimer invalidate]; gRefreshTimer = nil;
        gDraw.hidden = YES; gToast.hidden = YES;
        [self styleToggle:NO];
        return;
    }
    [self styleToggle:YES];
    [self refresh];
    gRefreshTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t){
        [RKOverlay refresh];
    }];
}

+ (void)styleToggle:(BOOL)on {
    gBtn.backgroundColor = on ? [[UIColor systemBlueColor] colorWithAlphaComponent:0.95]
                              : [[UIColor systemGreenColor] colorWithAlphaComponent:0.9];
    [gBtn setTitle:on ? @"👁 ON" : @"👁 손패" forState:UIControlStateNormal];
}

/* Hold AUTO to set how long each tile takes. */
+ (void)holdAuto:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    if (gSpeedPanel) { [self hideSpeedPanel]; return; }

    UIView *root = gWin.rootViewController.view;
    CGFloat w = 232, h = 92;
    CGRect b = root.bounds;
    CGFloat x = MIN(MAX(12, gAutoBtn.center.x - w / 2), b.size.width - w - 12);
    CGFloat y = MIN(gAutoBtn.frame.origin.y + gAutoBtn.frame.size.height + 8,
                    b.size.height - h - 12);

    UIView *p = [[UIView alloc] initWithFrame:CGRectMake(x, y, w, h)];
    p.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.85];
    p.layer.cornerRadius = 12;
    p.layer.zPosition = 100003;

    gSpeedLabel = [[UILabel alloc] initWithFrame:CGRectMake(12, 8, w - 24, 20)];
    gSpeedLabel.textColor = [UIColor whiteColor];
    gSpeedLabel.font = [UIFont boldSystemFontOfSize:13];
    [p addSubview:gSpeedLabel];

    UISlider *s = [[UISlider alloc] initWithFrame:CGRectMake(12, 30, w - 24, 28)];
    s.minimumValue = kAutoTickMin;
    s.maximumValue = kAutoTickMax;
    s.value = gAutoTick;
    [s addTarget:self action:@selector(speedChanged:)
        forControlEvents:UIControlEventValueChanged];
    [p addSubview:s];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(w - 74, 60, 62, 26);
    [close setTitle:@"닫기" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    close.titleLabel.font = [UIFont boldSystemFontOfSize:13];
    close.backgroundColor = [[UIColor whiteColor] colorWithAlphaComponent:0.18];
    close.layer.cornerRadius = 6;
    [close addTarget:self action:@selector(hideSpeedPanel)
    forControlEvents:UIControlEventTouchUpInside];
    [p addSubview:close];

    [root addSubview:p];
    gSpeedPanel = p;
    [self syncSpeedLabel];
}

+ (void)speedChanged:(UISlider *)s {
    gAutoTick = s.value;
    [[NSUserDefaults standardUserDefaults] setDouble:gAutoTick forKey:kAutoTickKey];
    [self syncSpeedLabel];
}

+ (void)syncSpeedLabel {
    gSpeedLabel.text = [NSString stringWithFormat:@"타일당 %.2f초", gAutoTick];
}

+ (void)hideSpeedPanel {
    [gSpeedPanel removeFromSuperview];
    gSpeedPanel = nil;
    gSpeedLabel = nil;
}

+ (void)styleAuto:(BOOL)on {
    gAutoBtn.backgroundColor = on ? [[UIColor systemRedColor] colorWithAlphaComponent:0.95]
                                  : [[UIColor systemOrangeColor] colorWithAlphaComponent:0.9];
    [gAutoBtn setTitle:on ? @"⏹ 중지" : @"⚙︎ AUTO" forState:UIControlStateNormal];
}
// One-shot: log every board/rack tile with its grid coords. This is how we learn
// the board coordinate convention for auto-place — read-only, on the tile-gather
// path that SOLVE already exercises (no extra hooks; hooking the move path and
// deep-dumping generic-heavy classes both destabilised the game when tried).
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
    // A run in flight means this tap is "stop". Its plan described the board as
    // it was when the run began, so there is nothing worth resuming later — the
    // next tap re-solves against whatever the board looks like then.
    if (gAutoTimer) {
        [gAutoTimer invalidate]; gAutoTimer = nil;
        [self styleAuto:NO];
        [self toast:@"자동배치 중지"];
        return;
    }
    ensureHooksMainThread();
    // Sort the rack before planning so tiles of the same run end up adjacent and
    // can be lifted as one block. Re-read the board afterwards, since the plan
    // has to describe where the tiles are *now*.
    static BOOL sortedThisRun = NO;
    if (!sortedThisRun) {
        sortedThisRun = YES;
        if (rkArrangeRack(1)) {                    // 1 = ArrangeByColor
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.35 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [RKOverlay autoTap]; });
            [self toast:@"핸드 정렬 중…"];
            return;
        }
    }
    sortedThisRun = NO;
    CGFloat H = gWin.bounds.size.height;
    CGFloat scale = gWin.screen.scale ?: [UIScreen mainScreen].scale;
    NSArray *tiles = rkGatherTiles(H, scale);
    if (!tiles.count) { [self toast:@"타일을 못 읽음 — 매치 화면에서"]; return; }
    id res = rkComputeFromTiles(tiles);
    if (![res isKindOfClass:[NSDictionary class]]) { [self toast:[res description]]; return; }

    // ---- detailed diagnostics: what the solver sees + decides ----
    {
        static const char *CC[4] = { "K", "Bl", "R", "Y" };
        NSMutableArray *hs = [NSMutableArray array], *bs2 = [NSMutableArray array];
        for (NSDictionary *t in tiles) {
            int c = [t[@"c"] intValue], n = [t[@"n"] intValue]; BOOL j = [t[@"j"] boolValue];
            NSString *lab = j ? @"JK" : [NSString stringWithFormat:@"%s%d", (c>=0&&c<4)?CC[c]:"?", n];
            if ([t[@"loc"] intValue] == 1 && [t[@"mine"] boolValue]) [hs addObject:lab];
            else if ([t[@"loc"] intValue] == 2)
                [bs2 addObject:[NSString stringWithFormat:@"%@@(%@,%@)", lab, t[@"gx"], t[@"gy"]]];
        }




    }

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
    // Board->board moves are legal now that the payload is right (attach = -1), so
    // plan the way a player actually rearranges: build each set the solver asked
    // for in free space and move its tiles there, instead of bolting rack tiles
    // onto whatever block happens to sit next door. That old rule could not express
    // "pull Blue 4 out of the group of 4s to start a Blue 4-5-6 run", which is the
    // shape most of the solver's answers take.
    static char occ[64][64];
    memset(occ, 0, sizeof(occ));
    for (NSDictionary *t in tiles) {
        if ([t[@"loc"] intValue] != 2) continue;
        int cx = [t[@"gx"] intValue] - bx, cy = [t[@"gy"] intValue] - by;
        if (cx >= 0 && cx < 64 && cy >= 0 && cy < 64) occ[cy][cx] = 1;
    }

    // A set is already done when its tiles are all on the board, in one row, in
    // consecutive cells, with a blank or the board edge at each end. Leave those
    // untouched and keep their cells reserved.
    NSMutableArray *todo = [NSMutableArray array];
    for (NSArray *set in sets) {
        BOOL allBoard = YES; int row = INT_MIN, lo = INT_MAX, hi = INT_MIN;
        for (NSDictionary *t in set) {
            if ([t[@"loc"] intValue] != 2) { allBoard = NO; break; }
            int gx = [t[@"gx"] intValue], gy = [t[@"gy"] intValue];
            if (row == INT_MIN) row = gy; else if (gy != row) { allBoard = NO; break; }
            lo = MIN(lo, gx); hi = MAX(hi, gx);
        }
        BOOL done = allBoard && (hi - lo + 1) == (int)set.count;
        if (done) {
            int r = row - by, l = lo - bx - 1, rr = hi - bx + 1;
            if (l >= 0 && occ[r][l]) done = NO;
            if (rr < bw && occ[r][rr]) done = NO;
        }
        if (!done) [todo addObject:set];
    }
    // Every tile of a set we are rebuilding vacates its cell, so that space is
    // available to the layout below.
    for (NSArray *set in todo)
        for (NSDictionary *t in set) {
            if ([t[@"loc"] intValue] != 2) continue;
            int cx = [t[@"gx"] intValue] - bx, cy = [t[@"gy"] intValue] - by;
            if (cx >= 0 && cx < 64 && cy >= 0 && cy < 64) occ[cy][cx] = 0;
        }
    // Sets that let me play tiles from my rack come first: those are the ones that
    // make progress, so they get the free space if it runs short.
    todo = [[todo sortedArrayUsingComparator:^NSComparisonResult(NSArray *a, NSArray *b) {
        int ra = 0, rb = 0;
        for (NSDictionary *t in a) if ([t[@"loc"] intValue] == 1) ra++;
        for (NSDictionary *t in b) if ([t[@"loc"] intValue] == 1) rb++;
        if (ra != rb) return ra > rb ? NSOrderedAscending : NSOrderedDescending;
        if (a.count != b.count) return a.count > b.count ? NSOrderedAscending : NSOrderedDescending;
        return NSOrderedSame;
    }] mutableCopy];

    NSMutableArray *targets = [NSMutableArray array];
    NSMutableArray *plans = [NSMutableArray array];   // ordered sets for the executor
    int noAnchor = 0, noSlot = 0;
    for (NSArray *set in todo) {
        [plans addObject:[@{ @"tiles": set, @"defer": @0 } mutableCopy]];
        // The game makes room by itself: dropping a tile onto a row shoves the
        // tiles to its right along (ClearSpaceForTilesOnRow) and grows the board
        // when it has to (EnlargeBoardByOneRow). So a set does not need a
        // pre-cleared strip — it needs one free cell to start on, whose LEFT
        // neighbour is blank. Requiring n free cells with blanks on both sides is
        // what produced "noSlot" and the "no free cell to evict into" dead end on
        // a board that in fact had room.
        //
        // The left side is the part that matters: a tile dropped immediately right
        // of a foreign block joins it, and the merged block is not a valid set, so
        // the game refuses the move (observed: Blue 11 next to another Blue 11,
        // refused a dozen times). Growing rightwards is safe because whatever sits
        // there gets pushed.
        int n = (int)set.count, sx = -1, sy = -1;
        for (int r = 0; r < bh + 8 && sx < 0; r++)
            for (int c = 0; c < bw; c++) {
                if (occ[r][c]) continue;                       // start on a blank
                if (c - 1 >= 0 && occ[r][c - 1]) continue;     // nothing joined on the left
                sx = c; sy = r; break;
            }
        if (sx < 0) { noSlot++; continue; }
        // Reserve the cells the set will end up in, so later sets pick a different
        // start; the tiles in between are the game's problem, not ours.
        for (int k = 0; k < n && sx + k < 64; k++) occ[sy][sx + k] = 1;
        NSMutableArray *ids = [NSMutableArray array];
        for (NSDictionary *t in set) [ids addObject:t[@"id"]];
        for (int i = 0; i < n; i++) {
            NSDictionary *t = set[i];
            int tx = bx + sx + i, ty = by + sy;
            if ([t[@"loc"] intValue] == 2 &&
                [t[@"gx"] intValue] == tx && [t[@"gy"] intValue] == ty) continue;
            // idx says where this tile sits in its set: index 0 needs a clean start
            // cell, the rest simply follow the tile before them.
            [targets addObject:@{ @"tiles": @[ t ], @"x": @(tx), @"y": @(ty), @"attach": @(-1),
                                  @"sx": @(bx + sx), @"ex": @(bx + sx + n - 1),
                                  @"idx": @(i), @"ids": ids }];
        }
    }

    // Full plan: every intended move, with its tiles and destination.
    {
        static const char *CC[4] = { "K", "Bl", "R", "Y" };
        for (NSUInteger i = 0; i < targets.count; i++) {
            NSDictionary *m = targets[i];
            NSMutableString *w = [NSMutableString string];
            for (NSDictionary *t in m[@"tiles"]) {
                int c = [t[@"c"] intValue], n = [t[@"n"] intValue];
                [w appendFormat:@"%@%@ ", [t[@"loc"] intValue]==1 ? @"rack:" : @"board:",
                 [t[@"j"] boolValue] ? @"JK" : [NSString stringWithFormat:@"%s%d",(c>=0&&c<4)?CC[c]:"?",n]];
            }

        }
    }
    if (!targets.count) { [self toast:@"배치할 세트 없음"]; return; }

    // Assemble set by set, tile by tile, always reading where tiles ACTUALLY are.
    // The game compacts a row as it applies a move, so a tile can land a column
    // away from the cell we named; a plan pinned to precomputed cells then thinks
    // nothing happened and re-fires the same move forever. Re-deriving the chain
    // from the live board each tick removes the whole idea of a move "failing":
    // whatever the game did, the next tile simply goes after the last one that
    // landed.
    [gAutoTimer invalidate];
    [self styleAuto:YES];
    __block NSMutableArray *sq = [plans mutableCopy];
    __block int ticks = 0, done = 0, idle = 0;
    __block NSTimeInterval t0 = CFAbsoluteTimeGetCurrent();   // to report how long a run takes
    __block NSTimeInterval acc = 0;
    gAutoTimer = [NSTimer scheduledTimerWithTimeInterval:kAutoPoll repeats:YES block:^(NSTimer *tm) {
        acc += kAutoPoll;
        if (acc + 1e-6 < gAutoTick) return;
        acc = 0;
        CGFloat hh = gWin.bounds.size.height, sc = gWin.screen.scale ?: [UIScreen mainScreen].scale;
        NSArray *live = rkGatherTiles(hh, sc);
        if (++ticks > 300 || !sq.count || !live.count || idle > 30) {
            [tm invalidate]; gAutoTimer = nil;
            [RKOverlay styleAuto:NO];

            // Report elapsed time: a turn is on a 30 s clock, so whether a run
            // fits is a measurement, not a guess.
            [RKOverlay toast:[NSString stringWithFormat:@"자동배치 종료 — %d수 %.1f초 (남은 세트 %lu)",
                              done, CFAbsoluteTimeGetCurrent() - t0, (unsigned long)sq.count]];
            return;
        }
        NSMutableDictionary *posOf = [NSMutableDictionary dictionary];
        NSMutableSet *occupied = [NSMutableSet set];
        for (NSDictionary *t in live) {
            posOf[t[@"id"]] = t;
            if ([t[@"loc"] intValue] == 2)
                [occupied addObject:[NSString stringWithFormat:@"%@,%@", t[@"gx"], t[@"gy"]]];
        }

        // Handle as many bookkeeping steps as needed in this tick and stop only
        // once a move actually goes out. Finishing a set used to `return`, so the
        // whole pacing interval elapsed with nothing happening — that was the
        // pause between sets.
        int spins = 0;
        while (sq.count && spins++ < 32) {
        NSMutableDictionary *cur = sq[0];
        NSArray *stiles = cur[@"tiles"];
        int n = (int)stiles.count;

        // Anchor on the longest run of the set that is ALREADY consecutive on the
        // board, wherever it sits in the set — not just a prefix starting at tile
        // 0. With a prefix rule, a set whose tiles 1..3 are already together but
        // whose tile 0 is still in the rack counted as nothing done, so the whole
        // set got torn down and rebuilt to add one tile.
        int coreI = -1, coreLen = 0, coreRow = 0, coreL = 0;
        for (int i = 0; i < n; i++) {
            NSDictionary *pi = posOf[((NSDictionary *)stiles[i])[@"id"]];
            if (!pi || [pi[@"loc"] intValue] != 2) continue;
            int row = [pi[@"gy"] intValue], x0 = [pi[@"gx"] intValue], len = 1, prev = x0;
            for (int j = i + 1; j < n; j++) {
                NSDictionary *pj = posOf[((NSDictionary *)stiles[j])[@"id"]];
                if (!pj || [pj[@"loc"] intValue] != 2) break;
                if ([pj[@"gy"] intValue] != row || [pj[@"gx"] intValue] != prev + 1) break;
                prev = [pj[@"gx"] intValue]; len++;
            }
            if (len > coreLen) { coreLen = len; coreI = i; coreRow = row; coreL = x0; }
        }
        int coreR = coreL + coreLen - 1;

        // How many of the set's tiles starting at index i already sit side by side
        // (same row, ascending cells) — in the rack or on the board. Those can ride
        // along in a single move, since MovedCards is a list and the game drags a
        // contiguous block as one unit. Sending them one at a time was pure waste.
        int (^runFrom)(int) = ^int(int i) {
            NSDictionary *pi = posOf[((NSDictionary *)stiles[i])[@"id"]];
            if (!pi) return 0;
            int loc = [pi[@"loc"] intValue], row = [pi[@"gy"] intValue], prev = [pi[@"gx"] intValue];
            int len = 1;
            for (int j = i + 1; j < n; j++) {
                NSDictionary *pj = posOf[((NSDictionary *)stiles[j])[@"id"]];
                if (!pj || [pj[@"loc"] intValue] != loc) break;
                if ([pj[@"gy"] intValue] != row || [pj[@"gx"] intValue] != prev + 1) break;
                prev = [pj[@"gx"] intValue]; len++;
            }
            return len;
        };
        // Same idea backwards: the run that ENDS at index i.
        int (^runEndingAt)(int) = ^int(int i) {
            int st = i;
            while (st > 0) {
                NSDictionary *pa = posOf[((NSDictionary *)stiles[st - 1])[@"id"]];
                NSDictionary *pb = posOf[((NSDictionary *)stiles[st])[@"id"]];
                if (!pa || !pb) break;
                if ([pa[@"loc"] intValue] != [pb[@"loc"] intValue]) break;
                if ([pa[@"gy"] intValue] != [pb[@"gy"] intValue]) break;
                if ([pa[@"gx"] intValue] + 1 != [pb[@"gx"] intValue]) break;
                st--;
            }
            return i - st + 1;
        };

        NSMutableDictionary *rowPop = [NSMutableDictionary dictionary];
        for (NSDictionary *t in live)
            if ([t[@"loc"] intValue] == 2)
                rowPop[t[@"gy"]] = @([rowPop[t[@"gy"]] intValue] + 1);

        // Finding a clean strip: a run of `need` free cells with a blank on the
        // left, so the first tile cannot merge into a foreign block.
        int (^freeStrip)(int, int *, int *) = ^int(int need, int *ox, int *oy) {
            // An untouched row first: a set seeded there cannot be shoved about.
            // As other sets take tiles out of a busy row the game compacts it, a
            // lone anchor slides left every tick and the tile trying to join never
            // catches up.
            for (int r = 0; r <= bh; r++)
                if (![rowPop objectForKey:@(by + r)]) { *ox = bx; *oy = by + r; return 1; }
            for (int pass = 0; pass < 2; pass++) {
                int want = pass == 0 ? need : 1;
                for (int r = 0; r <= bh; r++)
                    for (int c = 0; c < bw; c++) {
                        if ([occupied containsObject:
                             [NSString stringWithFormat:@"%d,%d", bx + c - 1, by + r]]) continue;
                        BOOL room = YES;
                        for (int q = 0; q <= want && room; q++)
                            if ([occupied containsObject:
                                 [NSString stringWithFormat:@"%d,%d", bx + c + q, by + r]]) room = NO;
                        if (!room) continue;
                        *ox = bx + c; *oy = by + r; return 1;
                    }
            }
            return 0;
        };

        if (coreLen == n) {                       // whole set together — just check its ends
            BOOL clean = ![occupied containsObject:[NSString stringWithFormat:@"%d,%d", coreL - 1, coreRow]] &&
                         ![occupied containsObject:[NSString stringWithFormat:@"%d,%d", coreR + 1, coreRow]];
            if (clean) { [sq removeObjectAtIndex:0]; idle = 0; continue; }
            // Assembled correctly, only a neighbour touching an end. That
            // neighbour is usually a tile another pending set is about to take
            // away, so wait a cycle instead of tearing down a set that is already
            // right and rebuilding it somewhere else — that was pure motion.
            int d = [cur[@"defer"] intValue];
            if (d <= (int)sq.count) {
                cur[@"defer"] = @(d + 1);
                [sq addObject:cur]; [sq removeObjectAtIndex:0];
                continue;
            }
        }

        // Move only what a player could actually pick up: one tile, or tiles that
        // are already side by side. Handing the game a set scattered across the
        // board and the rack in a single move works, but it is not a gesture a
        // human can make.
        //
        // Assembly is therefore: put the biggest grabbable piece down in an empty
        // row, then bring the other pieces onto its edge naming the card to attach
        // to. Attaching is what actually merges them — dropping a loose tile
        // *beside* a block just gets it pushed away again.
        NSArray *moveTiles = nil;
        int tx = INT_MIN, ty = 0, attach = -1;
        // Relocating a lone anchor out of a busy row helps only once. When no
        // empty row exists freeStrip hands back a slot in a busy row, and then the
        // tile just placed is immediately "a lone anchor in a busy row" again —
        // the condition re-triggers on its own result and the set never grows
        // (logged: K3 cycling 105 -> 107 -> 109 -> 105 forever).
        // Relocate an anchor only once it is demonstrably being pushed around.
        //
        // "Its row has other tiles in it" is too broad — plenty of sets assemble
        // fine in a busy row. But dropping the check entirely brings back the
        // chase: as other sets take tiles out of a row the game compacts it, the
        // anchor slides left every tick and the tile trying to join trails one
        // column behind forever (R10 after an anchor going 106 -> 104 -> 103).
        // So watch the anchor: if it has shifted since the last tick, that row is
        // moving underneath us and the set needs solid ground.
        NSNumber *anchorId = coreLen ? ((NSDictionary *)stiles[coreI])[@"id"] : nil;
        int anchorNow = coreLen ? coreL : INT_MIN;
        BOOL anchorSlid = NO;
        if (anchorId && [cur[@"anchorId"] isEqual:anchorId]) {
            anchorSlid = ([cur[@"anchorX"] intValue] != anchorNow);
        }
        if (anchorId) { cur[@"anchorId"] = anchorId; cur[@"anchorX"] = @(anchorNow); }
        BOOL loneInCrowd = (coreLen == 1 && anchorSlid && ![cur[@"reseeded"] boolValue]);

        if (coreLen >= 1 && !loneInCrowd) {
            int m = coreI + coreLen;
            if (m < n) {                                  // grow to the right
                int L = MAX(1, runFrom(m));
                moveTiles = [stiles subarrayWithRange:NSMakeRange(m, L)];
                tx = coreR + 1; ty = coreRow;
                attach = [((NSDictionary *)stiles[m - 1])[@"id"] intValue];
            } else {                                      // grow to the left
                int L = MAX(1, runEndingAt(coreI - 1));
                if (coreL - L < bx) L = 1;
                moveTiles = [stiles subarrayWithRange:NSMakeRange(coreI - L, L)];
                tx = coreL - L; ty = coreRow;
                attach = [((NSDictionary *)stiles[coreI])[@"id"] intValue];
            }
        } else {
            // Seed the set: the largest run it already has, moved somewhere stable.
            int bestI = 0, bestL = 0;
            for (int i = 0; i < n; i++) {
                int L = runFrom(i);
                if (L > bestL) { bestL = L; bestI = i; }
            }
            if (bestL < 1) { bestL = 1; bestI = 0; }
            int fx, fy;
            if (!freeStrip(n, &fx, &fy)) { [sq removeObjectAtIndex:0]; idle++; continue; }
            moveTiles = [stiles subarrayWithRange:NSMakeRange(bestI, bestL)];
            // leave a cell for whatever belongs before this piece
            tx = fx + (bestI > 0 ? 1 : 0); ty = fy;
            if (coreLen >= 1) cur[@"reseeded"] = @YES;   // one relocation per set
        }

        {
            static const char *CC[4] = { "K", "Bl", "R", "Y" };
            NSMutableString *w = [NSMutableString string];
            for (NSDictionary *t in moveTiles) {
                NSDictionary *pp = posOf[t[@"id"]];
                int c = [t[@"c"] intValue];
                [w appendFormat:@"%s%@@%@(%@,%@) ", (c>=0&&c<4)?CC[c]:"?", t[@"n"],
                 pp[@"loc"], pp[@"gx"], pp[@"gy"]];
            }
            RKLOG(@"[exec] core=[i=%d len=%d row=%d x=%d..%d] n=%d move[%@] -> (%d,%d) attach=%d",
                  coreI, coreLen, coreRow, coreL, coreR, n, w, tx, ty, attach);
        }
        void *md = rkBuildMove(moveTiles, tx, ty, attach);
        BOOL fired = md ? rkApplyMove(md) : NO;
        if (fired) { done++; idle = 0; } else idle++;
        rkSyncVisuals();          // model moved; drag the 3D tiles to match
        [RKOverlay toast:[NSString stringWithFormat:@"배치 중 %d수 %.1f초 — 세트 %lu개 남음",
                          done, CFAbsoluteTimeGetCurrent() - t0, (unsigned long)sq.count]];
        break;                    // one move per pacing interval
        }
    }];
}
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
         }
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
    // Both buttons are draggable. They sit over a live board, so wherever they
    // default to will sometimes be exactly where a tile needs to be reached.
    UIButton *btn = rkMakeButton(@"👁 손패", [UIColor systemGreenColor],
                                 CGRectMake(b.size.width - 92, 60, 78, 40),
                                 self, @selector(toggle));
    [root addSubview:btn];
    [root bringSubviewToFront:btn];
    gBtn = btn;

    UIButton *ab = rkMakeButton(@"⚙︎ AUTO", [UIColor systemOrangeColor],
                                CGRectMake(b.size.width - 92, 106, 78, 40),
                                self, @selector(autoTap));
    UILongPressGestureRecognizer *hold =
        [[UILongPressGestureRecognizer alloc] initWithTarget:self
                                                      action:@selector(holdAuto:)];
    hold.minimumPressDuration = 0.5;
    [ab addGestureRecognizer:hold];
    [root addSubview:ab];
    gAutoBtn = ab;
    rkLoadAutoTick();



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

    // keep the button on top even if the game adds views later
    [NSTimer scheduledTimerWithTimeInterval:1.0 repeats:YES block:^(NSTimer *tm){
        if (!btn.hidden && btn.superview) [btn.superview bringSubviewToFront:btn];
        // Arm the capture/observation hooks here rather than from the AUTO button,
        // so they are in place for moves the player makes by hand too.
        ensureHooksMainThread();
    }];

}
+ (void)drag:(UIPanGestureRecognizer *)g {
    UIView *host = g.view.superview;
    CGPoint t = [g translationInView:host];
    CGPoint c = CGPointMake(g.view.center.x + t.x, g.view.center.y + t.y);
    // Keep it reachable: a button dragged past the edge cannot be dragged back.
    CGFloat hw = g.view.bounds.size.width / 2, hh = g.view.bounds.size.height / 2;
    c.x = MAX(hw, MIN(host.bounds.size.width  - hw, c.x));
    c.y = MAX(hh, MIN(host.bounds.size.height - hh, c.y));
    g.view.center = c;
    [g setTranslation:CGPointZero inView:host];
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
        %init(VCDiag);
        pthread_t th; pthread_create(&th, NULL, reconEntry, NULL); pthread_detach(th);
        pthread_t th2; pthread_create(&th2, NULL, adEntry, NULL); pthread_detach(th2);
        pthread_t th3; pthread_create(&th3, NULL, overlayEntry, NULL); pthread_detach(th3);
    }
}
