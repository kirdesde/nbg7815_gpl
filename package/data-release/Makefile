#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
	
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/package.mk

PKG_NAME:=data-release
PKG_VERSION:=0.1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)
RELEASE_FILE_DIR:=$(PKG_BUILD_DIR)/ipkg_file
RSTRIP:=:

define Package/data-release
SECTION:=net
CATEGORY:=Zyxel Packages
TITLE:=This is a release package
DEPENDS:=+bluez-libs +bluez-utils +libcrypto +libcurl +libexpat +libfcgi +libfcgi.so +libglib-2.0 +libjson-c +libmesode +libpcre +libsqlite3 +libssl +libubox +libubus +libuci +libz +libzyutm +libbfd +liblzo +libpam +libevent +libip4tc +libip6tc +libiptext +libiptext4 +libiptext6 +libxtables +liblua +kmod-crypto-authenc +kmod-lib-crc-ccitt +kmod-gre +kmod-l2tp +kmod-nf-nat +kmod-crypto-ocf +kmod-sit +kmod-slhc +kmod-tun +kmod-ip6-tunnel +kmod-nat46 +kmod-nf-conntrack +fcgi +libnl +libnl-tiny +jansson +libstdcpp +kmod-ppp +kmod-pppoe +kmod-pptp +kmod-bonding +kmod-pppol2tp
KCONFIG:=CONFIG_NF_CONNTRACK_EVENTS=y CONFIG_NF_CONNTRACK_CHAIN_EVENTS=y
endef

define Build/Prepare
	@echo "---------!!! TODO: prepare ipkg !!!----------"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/ipkg_file/*.ipk $(PACKAGE_DIR)
	if [ ! -d "$(TOPDIR)/package/private" ]; then \
		$(CP) ./src/* $(PKG_BUILD_DIR); \
		cd "$(RELEASE_FILE_DIR)"; \
		for i in $$$$( ls ) ; do \
				tar -xf $$$$i; \
				mkdir tmp; \
				tar -zxvf data.tar.gz -C tmp; \
				rm  $$$$i; \
				rm control.tar.gz; \
				rm data.tar.gz; \
		done; \
	fi
	mkdir -p $(STAGING_DIR_HOST)/bin/
	$(CP) ./file/zyfw_genfw $(STAGING_DIR_HOST)/bin/
endef

define Build/Compile/Default
endef

define Build/Compile
	$(call Build/Compile/Default)
endef
	
define Package/data-release/install
	@echo "---------!!! TODO: install ipkg !!!----------"
	$(INSTALL_DIR) $(1)/
	$(CP) -rf $(RELEASE_FILE_DIR)/tmp/* $(1)/ 
endef

$(eval $(call BuildPackage,data-release))
