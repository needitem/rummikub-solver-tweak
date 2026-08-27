# Standalone (non-jailbroken) build

Builds the same `Tweak.xm` as a plain dylib to inject into a re-signed Rummikub
IPA, for a device with no jailbreak.

```bash
make            # -> .theos/obj/debug/rkstandalone.dylib
```

The only difference from the jailbreak package is `-DRK_STANDALONE=1`, which makes
the dylib define its own `MSHookMessageEx` using the ObjC runtime. Without that the
dylib would carry an undefined Substrate symbol and dyld would refuse to load it.
No inline-hooking library is needed — the tweak reaches everything through il2cpp
runtime calls.

## Getting it onto a device

1. **Decrypt.** Only the app's small launcher binary is FairPlay-encrypted
   (`UnityFramework` ships unencrypted). Read the decrypted pages out of a running
   copy on a jailbroken device with frida and write them over a local copy, then
   clear `cryptid` in `LC_ENCRYPTION_INFO_64`.
2. **Inject.** Copy `rkstandalone.dylib` into `Rummikub.app/Frameworks/`, set its
   install name to `@executable_path/Frameworks/rkstandalone.dylib`, and add a
   matching `LC_LOAD_DYLIB` to the main binary (`insert_dylib`).
3. **Re-sign.** Delete `SC_Info` and every `_CodeSignature`, point
   `CFBundleIdentifier` at an identifier your provisioning profile covers, drop the
   app's embedded profile in as `embedded.mobileprovision`, then codesign the dylib,
   each framework, and finally the bundle with the profile's entitlements.
4. **Install** with `xcrun devicectl device install app`.

Two things that will bite:

* The App Store build is **device-thinned**. Its `UISupportedDevices` lists only the
  models it was downloaded for, and installation is refused on anything else —
  remove the key.
* On a free developer account the provisioning profile lasts **7 days**, so the app
  has to be re-signed and reinstalled that often.

## Why there are no native hooks

Inline hooking cannot work here. Dobby installs the patch, but its trampoline lives
in memory the kernel will not make executable without the `dynamic-codesigning`
entitlement, so the game dies the instant it calls a hooked method. Dropping the
hooks turned out to be an improvement for the jailbreak build too — see the comment
above `installCaptureHook`.
