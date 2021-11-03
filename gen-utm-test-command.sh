#!/bin/sh

if [ ! -d "build_dir/" ]; then
  echo "build_dir/ not exist"
  exit 1
fi

BUILD_DIR="build_dir/target-aarch64_cortex-a53_musl-1.1.16"

if [ ! -d "$BUILD_DIR" ]; then
  echo "$BUILD_DIR not exist"
  exit 1
fi

if [ ! -d "$BUILD_DIR/cyber-security/" ]; then
  echo "$BUILD_DIR/cyber-security/ not exist"
  exit 1
fi

## check DID test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/deviceIdentify-daemon/" ]; then
  echo "$BUILD_DIR/cyber-security/deviceIdentify-daemon/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/deviceIdentify-daemon/devid_test" ]; then
    echo "DID test command not exist"
    exit 1
  fi
fi

## check anti-virus test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/anti-virus/" ]; then
  echo "$BUILD_DIR/cyber-security/anti-virus/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/anti-virus/avd_test" ]; then
    echo "anti-virus test command not exist"
    exit 1
  fi
fi

## check ips test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/ips-daemon/" ]; then
  echo "$BUILD_DIR/cyber-security/ips-daemon/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/ips-daemon/ips_lib_test" ]; then
    echo "ips test command not exist"
    exit 1
  fi
fi

## check ir test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/utm-ir-daemon/" ]; then
  echo "$BUILD_DIR/cyber-security/utm-ir-daemon/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/utm-ir-daemon/test_program" ]; then
    echo "ir test command not exist"
    exit 1
  fi
fi

## check app control test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/libzyutm/" ]; then
  echo "$BUILD_DIR/cyber-security/libzyutm/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/libzyutm/app_test" ]; then
    echo "app control test command not exist"
    exit 1
  fi
fi

## check content-filter test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/libzyutm/" ]; then
  echo "$BUILD_DIR/cyber-security/libzyutm/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/libzyutm/iuf_api_test" ]; then
    echo "content-filter test command not exist"
    exit 1
  fi
fi

## check zyutm test daemon exist
if [ ! -d "$BUILD_DIR/cyber-security/libzyutm/" ]; then
  echo "$BUILD_DIR/cyber-security/libzyutm/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/libzyutm/zyutm_common_test" ]; then
    echo "zyutm_common_test test command not exist"
    exit 1
  fi
fi

## check reset cf_app_policy test command
if [ ! -d "$BUILD_DIR/cyber-security/libzyutm/" ]; then
  echo "$BUILD_DIR/cyber-security/libzyutm/ not exist"
  exit 1
else
  if [ ! -f "$BUILD_DIR/cyber-security/libzyutm/cf_app_policy_reset" ]; then
    echo "cf_app_policy_reset test command not exist"
    exit 1
  fi
fi


if [ -d "build_dir/utm_test_command/" ]; then
  rm -rf build_dir/utm_test_command/
fi

mkdir build_dir/utm_test_command
cp $BUILD_DIR/cyber-security/deviceIdentify-daemon/devid_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/anti-virus/avd_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/ips-daemon/ips_lib_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/utm-ir-daemon/test_program build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/libzyutm/app_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/libzyutm/iuf_api_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/libzyutm/zyutm_common_test build_dir/utm_test_command/
cp $BUILD_DIR/cyber-security/libzyutm/cf_app_policy_reset build_dir/utm_test_command/

if [ -f "build_dir/utm-test-command.tgz" ]; then
  rm -rf build_dir/utm-test-command.tgz
fi

cd build_dir/utm_test_command/
tar zcf ../utm-test-command.tgz *

if [ -f "../utm-test-command.tgz" ]; then
  echo "Generate utm test command successful ,please check build_dir/utm-test-command.tgz file"
fi

cd ../..
rm -rf build_dir/utm_test_command/
