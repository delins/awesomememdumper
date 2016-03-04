LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS) 
APP_PLATFORM := android-24
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie 
LOCAL_CPP_FEATURES += exceptions
# give module name
LOCAL_MODULE    := awesomememdumper
# list your C files to compile
LOCAL_SRC_FILES := awesomememdumper.cpp classes.cpp
# this option will build executables instead of building library for android application.
include $(BUILD_EXECUTABLE)
