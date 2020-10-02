# go-tun2socks-build

Building and using `go-tun2socks` for V2Ray on Android. This library is used in [shadowsocksr-v2ray-android](https://github.com/xxf098/shadowsocksr-v2ray-android) for support V2Ray.

![build](https://github.com/xxf098/go-tun2socks-build/workflows/build/badge.svg?branch=master&event=push) 

## Setup

* install [go](https://golang.org/doc/install#download) (test under version 1.15.2)
* install [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile) and init with `gomobile init -v`
* install [JDK 8](https://openjdk.java.net/install/) (not jre)
* Download Android SDK and [NDK](https://developer.android.com/ndk/downloads) (test under SDK 29 and NDK r21d)


## Build
```bash
# proxy
export http_proxy=http://127.0.0.1:8087
export https_proxy=http://127.0.0.1:8087
# go
export GOPATH="~/go"
export PATH=$PATH:/usr/local/go/bin:~/go/bin
# android
export ANDROID_HOME=/path/to/Android/Sdk
export ANDROID_NDK_HOME=/path/to/Android/android-ndk-r21d

go get -d ./...

# Build an AAR
make android

# Build a Framework (not test)
make ios

# Both
make
```
