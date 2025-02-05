# 插件：包信息
PACKAGE_IDENTIFIER = com.pxx917144686.surge
PACKAGE_NAME = Surge_pxx
PACKAGE_VERSION = 0.4.1
PACKAGE_ARCHITECTURE = arm64 arm64e
PACKAGE_REVISION = 1540
PACKAGE_SECTION = Tweaks
PACKAGE_DEPENDS = mobilesubstrate (>= 0.9.5000), firmware (>= 14.0)
PACKAGE_DESCRIPTION = Surge for iOS

# 设置包信息
define Package/Surge
  Package: $(PACKAGE_IDENTIFIER)
  Name: $(PACKAGE_NAME)
  Version: $(PACKAGE_VERSION)
  Architecture: arm64 arm64e
  Maintainer: Nets
  Author: pxx917144686
  Section: $(PACKAGE_SECTION)
  Depends: $(PACKAGE_DEPENDS)
  Description: $(PACKAGE_DESCRIPTION)
endef






# iPhone SDK 路径
SDK_PATH = $(shell xcode-select --print-path)/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

# 直接输出到当前目录
export THEOS_PACKAGE_DIR = $(CURDIR)

# TARGET
ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.5

# 确保这些进程名称是正确的，如果进程名称不匹配，插件将无法注入到正确的应用中。
INSTALL_TARGET_PROCESSES = Surge-iOS

# 引入 Theos 的通用设置
include $(THEOS)/makefiles/common.mk

# 插件：名称
TWEAK_NAME = Surge

# 源代码文件
Surge_FILES = Tweak.x

# OpenSSL 配置路径
OPENSSL_PATH = /Users/pxx917144686/openssl-ios

# 启用 Objective-C ARC 管理内存，添加 OpenSSL 头文件路径
Surge_CFLAGS = -fobjc-arc -I$(OPENSSL_PATH)/include -I$(OPENSSL_PATH)/include/openssl

# 添加所需动态库
Surge_LDFLAGS = -L$(OPENSSL_PATH)/lib -lssl -lcrypto -framework UIKit -framework Foundation -lsubstrate


# Theos编译规则
include $(THEOS_MAKE_PATH)/tweak.mk

















# PS
# 报错：ld: warning: -multiply_defined is obsolete
# 解释：为什么会出现这个问题？
# 原因：新版本的 Apple 链接器 (ld64) 不再推荐使用 -multiply_defined；Theos 是为了兼容老的iOS，才默认加入了这个选项。
# 解决：在文件 theos/makefiles/targets/_common/darwin_tail.mk 中，找到删除：-multiply_defined




# PS：
# 报错：warning: ignoring file '/usr/local/Cellar/openssl@3/3.4.0/lib/libcrypto.3.dylib': found architecture 'x86_64', required architecture 'arm64e'

# 解释：英特尔的Mac x86_64 不匹配架构 OpenSSL 库。
# 检查： Mac架构方法，终端执行： uname -m
#                    输出： x86_64 表示 Intel Mac
#                    输出： arm64 表示 Apple Silicon Mac
# 解决Intel(x86_64)方法：
# 避免你耽误时间精力！理由：网络指导会产生 很多误导！会把你是Intel(x86_64) 实际是指导(arm64)的方法；
# 你使用Intel Mac（x86_64）在编译 iOS 插件时，目标架构应为 arm64 或 arm64e ；

# 一、下载 OpenSSL 官方源代码
# 终端执行下载文件：git clone https://github.com/openssl/openssl.git
# 终端执行cd OpenSSL，这是默认路径：cd openssl

# 终端执行：export PLATFORM="iPhoneOS"
# 终端执行：export SDK=$(xcrun --sdk iphoneos --show-sdk-path)
# 终端执行：export CC="$(xcrun --sdk iphoneos -f clang)"

# 设置支持多个架构，arm64 和 arm64e
# 终端执行：export ARCHS="arm64 arm64e"
# 终端执行：export CFLAGS="-arch arm64 -arch arm64e -isysroot $SDK -miphoneos-version-min=14.0"
# 终端执行：export LDFLAGS="-arch arm64 -arch arm64e -isysroot $SDK"

# 配置 OpenSSL 编译
# 终端执行：./Configure ios64-cross no-shared no-dso no-hw no-engine --prefix=$(PWD)/../openssl-ios


# 二、编译 OpenSSL：注意——> 时间 可能有点长！基于 你的电脑配置区别！
# 配置参数
# 终端执行： ./Configure ios64-cross no-shared no-dso no-hw no-engine --prefix=$(PWD)/../openssl-ios

# 清理缓存，避免旧文件干扰   
# 终端执行：make clean

# 编译OpenSSL   
# 终端执行：make

# 安装 OpenSSL 到指定目录   
# 终端执行：make install


# 三、验证你的编译是否是 arm64 架构：
# 终端执行：lipo -info ../openssl-ios/lib/libcrypto.a
# 终端执行：lipo -info ../openssl-ios/lib/libssl.a
# 成功的输出：libcrypto.a are: arm64 arm64e




