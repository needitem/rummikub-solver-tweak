export THEOS_PACKAGE_SCHEME = rootless
export ARCHS = arm64 arm64e
export TARGET = iphone:clang:16.5:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rkreader
rkreader_FILES = Tweak.xm
rkreader_CFLAGS = -fobjc-arc -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-variable -Wno-unused-but-set-variable
rkreader_FRAMEWORKS = Foundation UIKit QuartzCore

include $(THEOS)/makefiles/tweak.mk
