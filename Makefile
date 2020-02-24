GOMOBILE=gomobile
GOBIND=$(GOMOBILE) bind
BUILDDIR=$(shell pwd)/build
LDFLAGS='-s -w'
IMPORT_PATH=github.com/xxf098/go-tun2socks-build

ANDROID_ARTIFACT=$(BUILDDIR)/tun2socks.aar
ANDROID_TARGET=android
ANDROID_BUILD_SCRIPT="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=$(ANDROID_TARGET) -o $(ANDROID_ARTIFACT) $(IMPORT_PATH)"

IOS_ARTIFACT=$(BUILDDIR)/Tun2socks.framework
IOS_TARGET=ios
IOS_BUILD_SCRIPT="cd $(BUILDDIR) && $(GOBIND) -a -ldflags $(LDFLAGS) -target=$(IOS_TARGET) -o $(IOS_ARTIFACT) $(IMPORT_PATH)"

all: ios android

ios:
	mkdir -p $(BUILDDIR)
	eval $(IOS_BUILD_SCRIPT)

android:
	mkdir -p $(BUILDDIR)
	eval $(ANDROID_BUILD_SCRIPT)

clean:
	rm -rf $(BUILDDIR)
