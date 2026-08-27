# Standalone (non-jailbroken) build of rkreader.
#
# Same Tweak.xm as the jailbreak package, but compiled with RK_STANDALONE so the
# dylib supplies its own MSHookMessageEx (via the ObjC runtime) instead of
# expecting ElleKit to provide it. No inline-hooking library is needed: the tweak
# reaches everything it needs through il2cpp runtime calls. The product is a plain
# dylib to inject into a re-signed Rummikub IPA, so there is no control file and
# no filter plist here.

export ARCHS = arm64
export TARGET = iphone:clang:16.5:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rkstandalone
rkstandalone_FILES = Tweak.xm
rkstandalone_CFLAGS = -fobjc-arc -DRK_STANDALONE=1 -I$(THEOS_PROJECT_DIR) \
	-Wno-unused-function -Wno-deprecated-declarations \
	-Wno-unused-variable -Wno-unused-but-set-variable
rkstandalone_FRAMEWORKS = Foundation UIKit QuartzCore
rkstandalone_INSTALL_PATH = /Applications

include $(THEOS)/makefiles/tweak.mk
