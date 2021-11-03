include $(TOPDIR)/rules.mk

PKG_NAME:=libmesode
PKG_VERSION:=master
PKG_RELEASE=1

PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=COPYING

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=$(SVN_REPOSITORY_ROOT)/openwrt/dl/
PKG_SOURCE_PROTO:=svn_pkg
PKG_SOURCE_VERSION:=HEAD

PKG_FIXUP:=autoreconf
PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/libmesode
  SECTION:=libs
  CATEGORY:=Libraries
  TITLE:=Fork of libstrophe XMPP Client
  URL:=https://github.com/boothj5/libmesode
  DEPENDS:= +libopenssl +libxml2 +libexpat
endef

define Package/libmesode/description
 libmesode is a fork of libstrophe (http://strophe.im/libstrophe/) for use in Profanity (http://www.profanity.im/).
endef

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include
	$(CP) $(PKG_BUILD_DIR)/mesode.h $(1)/usr/include/
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/.libs/libmesode.so* $(1)/usr/lib
endef

define Package/libmesode/install
	$(INSTALL_DIR) $(1)/usr/lib/
	$(CP) $(PKG_BUILD_DIR)/.libs/libmesode.so* $(1)/usr/lib
endef

$(eval $(call BuildPackage,libmesode))
