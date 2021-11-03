
ZYXEL_BIN_DIR = $(BIN_DIR)/zyxel
BLOCK_SIZE = 512
MKIMAGE = mkimage

ZYXEL_GENFW = zyfw_genfw

ifneq ($(CONFIG_ZYXEL_PROJECT_NAME),)
PROJECT_NAME := $(CONFIG_ZYXEL_PROJECT_NAME)
else
PROJECT_NAME := "NBGWXYZ"
endif

ifneq ($(CONFIG_ZYXEL_PROJECT_VERSION),)
PROJECT_VERSION := $(CONFIG_ZYXEL_PROJECT_VERSION)
else
PROJECT_VERSION := "V1.00(WXYZ.0)B0"
endif

ZLD_VERSION := "0.0.5"

define Image/zyxel/ras
	@echo create zyxel firmware image for project $(PROJECT_NAME) version $(PROJECT_VERSION) ...
	mkdir -p $(ZYXEL_BIN_DIR)
	dd if=$(BIN_DIR)/$(IMG_PREFIX)-qcom-ipq807x-zyxel-fit-uImage.itb of=$(ZYXEL_BIN_DIR)/$(IMG_PREFIX)-qcom-ipq807x-zyxel-fit-uImage.itb.padded bs=$(BLOCK_SIZE) conv=sync
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-squashfs-root.img $(ZYXEL_BIN_DIR)
	$(CP) $(PLATFORM_SUBDIR)/prebuilt_images/* $(ZYXEL_BIN_DIR)
	$(MKIMAGE) -f $(ZYXEL_BIN_DIR)/fit-zyxel.its $(ZYXEL_BIN_DIR)/fit-zyxel_fw.img
	$(ZYXEL_GENFW) -i $(ZYXEL_BIN_DIR)/fit-zyxel_fw.img -o $(ZYXEL_BIN_DIR)/ras.bin -P $(PROJECT_NAME) -V $(PROJECT_VERSION) -m $(ZYXEL_BIN_DIR)/header.bin -z $(ZLD_VERSION)
	@echo create zyxel firmware image ... done
endef
