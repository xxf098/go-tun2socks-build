GOMOBILE=gomobile
GOBIND=$(GOMOBILE) bind
BUILDDIR=$(shell pwd)/build
IOS_ARTIFACT=$(BUILDDIR)/Tun2socks.framework
ANDROID_ARTIFACT=$(BUILDDIR)/tun2socks.aar
IOS_TARGET=ios
ANDROID_TARGET=android
LDFLAGS='-s -w'
IMPORT_PATH=github.com/xxf098/go-tun2socks-build

BUILD_IOS="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=$(IOS_TARGET) -o $(IOS_ARTIFACT) $(IMPORT_PATH)"
BUILD_ANDROID="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=$(ANDROID_TARGET) -o $(ANDROID_ARTIFACT) $(IMPORT_PATH)"

all: ios android

ios:
	mkdir -p $(BUILDDIR)
	eval $(BUILD_IOS)

android:
	rm -rf $(BUILDDIR) 2>/dev/null
	mkdir -p $(BUILDDIR)
	eval $(BUILD_ANDROID)

clean:
	rm -rf $(BUILDDIR)
