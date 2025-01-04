# 包信息
PACKAGE_IDENTIFIER = com.pxx917144686.surge
PACKAGE_NAME = Surge_pxx
PACKAGE_VERSION = 0.1
PACKAGE_REVISION = 54
PACKAGE_SECTION = Tweaks
PACKAGE_DEPENDS = mobilesubstrate (>= 0.9.5000), firmware (>= 14.0)
PACKAGE_DESCRIPTION = Surge for iOS 测试一下～ //@pxx
PACKAGE_ICON = icon/icon.png

# 设置输出目录为项目目录（不使用 packages 目录）
export THEOS_PACKAGE_DIR = $(CURDIR)

# 设置构建目标平台，iphone:clang:latest:16.5 表示针对 iOS 16.5 版本编译
TARGET = iphone:clang:latest:16.5

# 指定 Tweak 将注入的目标进程
INSTALL_TARGET_PROCESSES = Surge-iOS Surge-iOS-NE

# 引入 Theos 的通用设置
include $(THEOS)/makefiles/common.mk

# 设置 Tweak 名称
TWEAK_NAME = Surge

# 设置源代码文件（仅包含 Tweak.x）
Surge_FILES = Tweak.x

# 设置编译选项，启用 Objective-C ARC 管理内存，并添加 OpenSSL 头文件路径
Surge_CFLAGS = -fobjc-arc -I/usr/local/opt/openssl@3/include

# 设置 OpenSSL 路径（根据实际情况修改）
OPENSSL := /usr/local/opt/openssl@3

# 添加 OpenSSL 的库文件路径到 Surge 的链接选项
Surge_LDFLAGS += -L$(OPENSSL)/lib

# 链接 OpenSSL 的 SSL 和 Crypto 库
Surge_LIBRARIES += ssl crypto

# 链接 Substrate
Surge_LIBRARIES += substrate

# 引入 Theos 的 Tweak 编译规则
include $(THEOS_MAKE_PATH)/tweak.mk

# 设置包信息
define PACKAGE
Package: $(PACKAGE_IDENTIFIER)
Name: $(PACKAGE_NAME)
Version: $(PACKAGE_VERSION)
Architecture: $(THEOS_PACKAGE_ARCH)
Maintainer: Nets
Author: pxx917144686
Section: $(PACKAGE_SECTION)
Depends: $(PACKAGE_DEPENDS)
Description: $(PACKAGE_DESCRIPTION)
Icon: $(PACKAGE_ICON)
endef
