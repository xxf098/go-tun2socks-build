# go-tun2socks-build

Demo for building and using `go-tun2socks` on Android.

## Setup

* install go (only test under version 1.13.5)
* install gomobile and init with `gomobile init -v`
* Download Android SDK and NDK (only test under SDK 29 and NDK r20b)


## Build
```bash
export http_proxy=http://127.0.0.1:8087
export https_proxy=http://127.0.0.1:8087
export ANDROID_HOME=/path/to/Android/Sdk
export ANDROID_NDK_HOME=/path/to/Android/android-ndk-r20b

go get -d ./...

# Build an AAR
make android
```
