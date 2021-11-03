include $(TOPDIR)/rules.mk

PKG_NAME:=dcmp-server
PKG_VERSION := 1.0

include $(INCLUDE_DIR)/package.mk

define Package/dcmp-server
  SECTION:=utils
  CATEGORY:=Zyxel Packages
  TITLE:=Decompression Server for DPI
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		DESTDIR="$(PKG_INSTALL_DIR)" \
		CC="$(TARGET_CC)" \
		CFLAGS+="-I$(STAGING_DIR)/usr/include -L$(STAGING_DIR)/usr/lib $(TARGET_CFLAGS)" \
		all
endef

define Package/dcmp-server/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/decomp_server $(1)/usr/bin/
endef

$(eval $(call BuildPackage,dcmp-server))
