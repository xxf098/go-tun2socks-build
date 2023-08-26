# go-tun2socks-build

Building and using `go-tun2socks` for V2Ray on Android. This library is used in [shadowsocksr-v2ray-trojan-android](https://github.com/xxf098/shadowsocksr-v2ray-trojan-android) for support V2Ray.

![build](https://github.com/xxf098/go-tun2socks-build/workflows/build/badge.svg?branch=master&event=push) 

## Setup

* install [go](https://golang.org/doc/install#download) (test with version 1.21.0)
* install [gomobile](https://godoc.org/golang.org/x/mobile/cmd/gomobile) with`go install golang.org/x/mobile/cmd/gomobile@latest`, then init with `gomobile init -v`
* install [JDK 8](https://openjdk.java.net/install/) (not jre)
* Download Android SDK and [NDK](https://developer.android.com/ndk/downloads) (test with SDK 30 and NDK r21e)


## Build
```bash
# china only
export GOPROXY=https://goproxy.cn
# setup go env
export GOPATH="/home/xxx/go"
export PATH=$PATH:/usr/local/go/bin:~/go/bin
# setup android env
export ANDROID_HOME=/path/to/Android/Sdk
export ANDROID_NDK_HOME=/path/to/Android/android-ndk-r21d

go get -d ./...

# Build an AAR
make android

```

## Useage

