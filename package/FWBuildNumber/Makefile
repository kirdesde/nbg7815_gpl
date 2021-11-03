include $(TOPDIR)/rules.mk

PKG_NAME:=FWBuildNumber
PKG_RELEASE:=1
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/FWBuildNumber
	SECTION:=net
	CATEGORY:=Zyxel Packages
	TITLE:=FWBuildNumber
endef

define Package/FWBuildNumber/description
	BuildNumber
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./source_code/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(call Build/Prepare)
	$(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/FWBuildNumber/install
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/BuildNumber $(1)/etc
endef

$(eval $(call BuildPackage,FWBuildNumber))


