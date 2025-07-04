#
# Copyright (C) 2025 WhereAreBugs <wherearebugs@icloud.com>
#
# This is free software, licensed under the MIT License.
#

# 引入 OpenWrt 的标准规则
include $(TOPDIR)/rules.mk
# 引入 CMake 的构建辅助工具
include $(INCLUDE_DIR)/cmake.mk

define Package/port-sharer
  PKG_NAME:=port-sharer
  PKG_VERSION:=1.4.0
  PKG_RELEASE:=1
  PKG_MAINTAINER:=WhereAreBugs <wherearebugs@icloud.com>
  PKG_LICENSE:=MIT
  PKG_LICENSE_FILES:=LICENSE
  PKG_SOURCE_PROTO:=git
  PKG_SOURCE_URL:=https://github.com/WhereAreBugs/port-sharer.git
  CMAKE_SOURCE_SUBDIR:=.
  CMAKE_OPTIONS:=-DCMAKE_BUILD_TYPE=Release -DFLAG_OPENWRT=1
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=A Layer-7 traffic dispatcher for port sharing and reuse
  URL:=https://github.com/WhereAreBugs/port-sharer.git
  DEPENDS:=+libstdcpp +boost-system +boost-thread +libuci
endef

define Package/port-sharer/description
  Port Sharer is a high-performance, intelligent Layer-7 traffic dispatcher
  that allows sharing a single port for multiple protocols.
  It inspects incoming data to identify protocols like HTTP, TLS (with SNI parsing),
  SSH, etc., and forwards traffic based on a flexible, UCI-configurable ruleset.
endef

# 定义如何将编译好的文件安装到固件中
define Package/port-sharer/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/port-sharer $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/port-sharer.init $(1)/etc/init.d/port-sharer
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/port-sharer.conf $(1)/etc/config/port_sharer
endef

# 定义安装后执行的脚本
define Package/port-sharer/postinst
#!/bin/sh
if [ -d /etc/rc.d ]; then
    /etc/init.d/port-sharer enable
fi
exit 0
endef

# 调用 OpenWrt 的构建宏来生成最终的包定义
$(eval $(call BuildPackage,port-sharer))