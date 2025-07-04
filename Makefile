
include $(TOPDIR)/rules.mk

PKG_NAME:=httpPortReuse
PKG_VERSION:=1.1
PKG_RELEASE:=1

PKG_MAINTAINER:=WhereAreBugs <wherearebugs@icloud.com>
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/httpPortReuse
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=A Layer-7 traffic dispatcher for port reuse
  DEPENDS:=+libstdcpp +boost-system +boost-thread
endef

define Package/httpPortReuse/description
  A high-performance L7 dispatcher that allows reusing a single port
  for different protocols. It inspects incoming data to identify
  HTTP/TLS traffic and forwards it to a specific port, while other
  traffic is sent to another port.
  Built with C++ and Boost.Asio.
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CXX) $(TARGET_CXXFLAGS) \
		-o $(PKG_BUILD_DIR)/httpPortReuse \
		$(PKG_BUILD_DIR)/asio_dispatcher_v2.cpp \
		$(TARGET_LDFLAGS) -lboost_system -lboost_thread -lpthread
endef


define Package/httpPortReuse/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/httpPortReuse $(1)/usr/bin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DATA) ./files/httpPortReuse.init $(1)/etc/init.d/httpPortReuse
	chmod 0755 $(1)/etc/init.d/httpPortReuse
endef

define Package/httpPortReuse/postinst
#!/bin/sh
if [ -d /etc/rc.d ]; then
    /etc/init.d/httpPortReuse enable
fi
exit 0
endef


$(eval $(call BuildPackage,httpPortReuse))
