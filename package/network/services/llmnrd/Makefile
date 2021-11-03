include $(TOPDIR)/rules.mk

PKG_NAME:=llmnrd

PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/llmnrd
	SECTION:=net
	CATEGORY:=Network
	TITLE:=llmnrd
	DEFAULT:=y
endef

define Package/llmnrd/description
	Support LLMNR protocol.
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/llmnrd/compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CROSS_COMPILE="$(TARGET_CROSS)"
endef

define Package/llmnrd/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/llmnrd $(1)/usr/sbin
endef

$(eval $(call BuildPackage,llmnrd))


