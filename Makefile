##############
## Variables #
##############
#
## S2E variables
S2EROOT?=/home/$(USER)/Mousse
S2ESRC?=$(S2EROOT)/mousse_source
S2EPREFIX?=$(SYSROOT)/usr
S2EBUILD:=$(S2EROOT)/mousse_build

# Set the number of parallel build jobs
OS:=$(shell uname)
ifeq ($(PARALLEL), no)
JOBS:=1
else ifeq ($(OS),Darwin)
JOBS:=$(patsubst hw.ncpu:%,%,$(shell sysctl hw.ncpu))
else ifeq ($(OS),Linux)
JOBS:=$(shell grep -c ^processor /proc/cpuinfo)
endif

UBUNTU_VERSION := $(shell lsb_release -a 2>/dev/null | grep Release | cut -f 2)

MAKE:=make -j$(JOBS)

CLANG_CC = $(CLANG)
CLANG_CXX = $(CXXCLANG)
CFLAGS_ARCH:=$(CFLAGS)
CXXFLAGS_ARCH:=$(CXXFLAGS)

# LLVM variables
LLVMBUILD?=$(S2EBUILD)
ifeq ($(LLVMBUILD),$(S2EBUILD))
LLVM_DIRS=llvm-native llvm-debug llvm-release
endif

LLVM_VERSION=3.9.0
LLVM_SRC=llvm-$(LLVM_VERSION).src.tar.xz
LLVM_SRC_DIR=llvm-$(LLVM_VERSION).src
LLVM_SRC_URL = http://llvm.org/releases/$(LLVM_VERSION)

CLANG_SRC=clang+llvm-$(LLVM_VERSION)-x86_64-linux-gnu-ubuntu-16.04.tar.xz
CLANG_SRC_DIR=clang+llvm-$(LLVM_VERSION)-x86_64-linux-gnu-ubuntu-16.04
CLANG_DEST_DIR=$(LLVM_SRC_DIR)/tools/clang

# Z3 variables
Z3_VERSION=4.6.0
Z3_SRC=z3-$(Z3_VERSION).tar.gz
Z3_SRC_DIR=z3-z3-$(Z3_VERSION)
Z3_BUILD_DIR=z3
Z3_URL=https://github.com/Z3Prover/z3

# Lua variables
LUA_VERSION=5.3.4
LUA_SRC=lua-$(LUA_VERSION).tar.gz
LUA_DIR=lua-$(LUA_VERSION)

KLEE_DIRS=$(foreach suffix,-debug -release,$(addsuffix $(suffix),klee))
#
############
## Targets #
############
#klee-debug: stamps/klee-debug-make
#libvmi-debug: stamps/libvmi-debug-make
#libfsig-debug: stamps/libfsigc++-debug-make
#libq-debug:	stamps/libq-debug-make
all-debug: stamps/libs2e-debug-make

clean:
	-rm -Rf $(KLEE_DIRS)
	-rm -Rf $(Z3_SRC_DIR) $(Z3_BUILD_DIR)
	-rm -Rf stamps

# From https://stackoverflow.com/questions/4219255/how-do-you-get-the-list-of-targets-in-a-makefile
list:
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null |                                  \
		awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | \
		sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

.PHONY: all all-debug
.PHONY: clean 
.PHONY: list

ALWAYS:

$(KLEE_DIRS) $(LLVM_DIRS) libq-debug                          \
libfsigc++-debug libvmi-debug                 \
libs2e-debug            \
stamps:
	mkdir -p $@
stamps/%-configure: | % stamps
	cd $* && $(CONFIGURE_COMMAND)
	touch $@

stamps/%-make:
	$(MAKE) -C $* $(BUILD_OPTS)
	touch $@

##############
## Downloads #
##############

ifeq ($(LLVMBUILD),$(S2EBUILD))
# Download LLVM
$(LLVM_SRC) $(CLANG_SRC):
	wget $(LLVM_SRC_URL)/$@


$(LLVM_SRC_DIR): $(LLVM_SRC) $(CLANG_SRC_DIR)
	tar -xmf $<
	cp $(S2EROOT)/mousse_scripts/patches/llvm.mousse.patch ./
	patch -p0 < llvm.mousse.patch

$(CLANG_SRC_DIR): $(CLANG_SRC)
	tar -xmf $<

else
# Use the specified LLVM build folder, don't build LLVM
endif

# Download Lua
$(LUA_SRC):
	wget http://www.lua.org/ftp/$(LUA_SRC)

$(LUA_DIR): | $(LUA_SRC)
	tar -zxf $(LUA_SRC)
	cp $(S2EROOT)/mousse_scripts/patches/lua.mousse.patch ./
	patch -p0 < lua.mousse.patch

# Download Z3
$(Z3_BUILD_DIR):
	wget $(Z3_URL)/archive/$(Z3_SRC)
	tar -zxf $(Z3_SRC)
	cp $(S2EROOT)/mousse_scripts/patches/z3.mousse.patch ./
	patch -p0 < z3.mousse.patch
	mkdir -p $(S2EBUILD)/$(Z3_BUILD_DIR)

# Download SOCI
$(SOCI_BUILD_DIR):
	git clone $(SOCI_GIT_URL) $(SOCI_SRC_DIR)
	cd $(SOCI_SRC_DIR) && git checkout $(SOCI_GIT_REV)
	mkdir -p $(S2EBUILD)/$(SOCI_BUILD_DIR)

ifeq ($(LLVMBUILD),$(S2EBUILD))


########
# LLVM #
########

# Make sure to build the system with a known version of the compiler.
# We use pre-built clang binaries for that.
CFLAGS_ARCH_LLVM=$(CFLAGS_ARCH) -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=hard -target arm-linux-androideabi
CXXFLAGS_ARCH_LLVM=$(CXXFLAGS_ARCH) -march=armv7-a -mcpu=cortex-a9 -mfloat-abi=hard -target arm-linux-androideabi
stamps/llvm-native-make: $(LLVM_SRC_DIR) | stamps
	touch $@
LLVM_CONFIGURE_FLAGS = -DLLVM_TARGETS_TO_BUILD="ARM"        \
                       -DLLVM_TARGET_ARCH="ARM"          \
		               -DLLVM_DEFAULT_TARGET_TRIPLE=arm-linux-androideabi	\
                       -DCMAKE_CROSSCOMPILING=True          \
		               -DCLANG_TABLEGEN=$(S2EBUILD)/$(CLANG_SRC_DIR)/bin/clang-tblgen   \
		               -DCMAKE_VERBOSE_MAKEFILE=ON	\
		               -DLLVM_TABLEGEN=$(S2EBUILD)/$(CLANG_SRC_DIR)/bin/llvm-tblgen	\
                       -DLLVM_INCLUDE_EXAMPLES=Off          \
                       -DLLVM_INCLUDE_DOCS=Off              \
                       -DLLVM_ENABLE_RTTI=On                \
                       -DLLVM_ENABLE_EH=On                  \
                       -DENABLE_ASSERTIONS=On               \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS=$(CFLAGS_ARCH)       \
                       -DCMAKE_CXX_FLAGS=$(CXXFLAGS_ARCH)   \
                       -G "Unix Makefiles"

stamps/llvm-debug-configure: stamps/llvm-native-make
stamps/llvm-debug-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)  \
                                                 -DCMAKE_BUILD_TYPE=Debug       \
                                                 $(LLVMBUILD)/$(LLVM_SRC_DIR)


stamps/llvm-debug-make: stamps/llvm-debug-configure

else
stamps/llvm-release-make:
	echo "Won't build"
stamps/llvm-debug-make:
	echo "Won't build"
stamps/llvm-native-make:
	echo "Won't build"
endif

#######
## Z3 #
#######

Z3_CONFIGURE_FLAGS = -DCMAKE_CROSSCOMPILING="True"                      \
                     -DCMAKE_PREFIX_PATH=$(SYSROOT)                     \
                     -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)                \
                     -DCMAKE_C_COMPILER=$(CLANG_CC)                     \
                     -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                  \
                     -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -fPIC"    \
                     -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -fPIC"  \
                     -DBUILD_LIBZ3_SHARED=Off                           \
                     -DUSE_OPENMP=Off                                   \
                     -G "Unix Makefiles"

stamps/z3-configure: stamps/llvm-native-make $(Z3_BUILD_DIR)
	cd $(Z3_SRC_DIR) &&                                         \
	python contrib/cmake/bootstrap.py create
	cd $(Z3_BUILD_DIR) &&                                       \
	cmake $(Z3_CONFIGURE_FLAGS) $(S2EBUILD)/$(Z3_SRC_DIR)
	touch $@

stamps/z3-make: stamps/z3-configure
	$(MAKE) -C $(Z3_BUILD_DIR)
	$(MAKE) -C $(Z3_BUILD_DIR) install
	touch $@


########
## Lua #
########

stamps/lua-make: $(LUA_DIR)
	$(MAKE) -C $^ linux CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIE -pie"
	touch $@

########
# KLEE #
########
KLEE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)                                  \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                       -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"   \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                       -DCMAKE_CROSSCOMPILING=True          \
		               -DCMAKE_PREFIX_PATH=$(SYSROOT)	\
                       -DUSE_CMAKE_FIND_PACKAGE_LLVM=On                                     \
                       -DENABLE_TESTS=Off                                                   \
                       -DENABLE_DOCS=Off                                                    \
                       -DENABLE_SOLVER_Z3=On                                                \
                       -DZ3_INCLUDE_DIRS=$(S2EPREFIX)/include                               \
                       -DZ3_LIBRARIES=$(S2EPREFIX)/lib/libz3.a

stamps/klee-debug-configure: stamps/llvm-debug-make stamps/z3-make 
stamps/klee-debug-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVMBUILD)/llvm-debug/lib/cmake/llvm  \
                                                 $(S2ESRC)/klee
stamps/klee-debug-make: stamps/klee-debug-configure

##########
# LibVMI #
##########

LIBVMI_COMMON_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)           \
                      -DCMAKE_MODULE_PATH=$(S2ESRC)/cmake           \
                      -DCMAKE_C_COMPILER=$(CLANG_CC)                \
                      -DCMAKE_CXX_COMPILER=$(CLANG_CXX)             \
                      -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fPIC"        \
                      -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fPIC"    \
                      -G "Unix Makefiles"

stamps/libvmi-debug-configure: stamps/llvm-debug-make
stamps/libvmi-debug-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                         \
                                                   -DLLVM_DIR=$(LLVMBUILD)/llvm-debug/lib/cmake/llvm    \
                                                   -DCMAKE_BUILD_TYPE=Debug                             \
                                                   $(S2ESRC)/libvmi

stamps/libvmi-debug-make: stamps/libvmi-debug-configure


stamps/libvmi-debug-install: stamps/libvmi-debug-make
	$(MAKE) -C libvmi-debug install
	touch $@

##############
# libfsigc++ #
##############

#TODO: factor out common flags

LIBFSIGCXX_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2ESRC)/cmake   \
                    	  -DCMAKE_CROSSCOMPILING=True          \
		    	          -DCMAKE_PREFIX_PATH=$(SYSROOT)	\
                          -DCMAKE_C_COMPILER=$(CLANG_CC)        \
                          -DCMAKE_CXX_COMPILER=$(CLANG_CXX)     \
                          -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"      \
                          -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH)"  \
                          -G "Unix Makefiles"

stamps/libfsigc++-debug-configure: stamps/llvm-native-make

stamps/libfsigc++-debug-configure: CONFIGURE_COMMAND = cmake $(LIBFSIGCXX_COMMON_FLAGS) \
                                                       -DCMAKE_BUILD_TYPE=Debug         \
                                                       $(S2ESRC)/libfsigc++
stamps/libfsigc++-debug-make: stamps/libfsigc++-debug-configure

########
# libq #
########

LIBQ_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2ESRC)/cmake     \
                    -DCMAKE_C_COMPILER=$(CLANG_CC)          \
                    -DCMAKE_CROSSCOMPILING=True          \
		            -DCMAKE_PREFIX_PATH=$(SYSROOT)	\
                    -DCMAKE_CXX_COMPILER=$(CLANG_CXX)       \
                    -DCMAKE_C_FLAGS="$(CFLAGS_ARCH)"        \
                    -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH)"    \
                    -G "Unix Makefiles"

stamps/libq-debug-configure: stamps/llvm-native-make

stamps/libq-debug-configure: CONFIGURE_COMMAND = cmake $(LIBQ_COMMON_FLAGS) \
                                                 -DCMAKE_BUILD_TYPE=Debug   \
                                                 $(S2ESRC)/libq


stamps/libq-debug-make: stamps/libq-debug-configure

########
# QEMU #
########

#Yingtong
#QEMU_TARGETS=i386-softmmu,x86_64-softmmu
QEMU_TARGETS=x86_64-linux-user

QEMU_CONFIGURE_FLAGS = --prefix=$(S2EPREFIX)         \
                       --target-list=$(QEMU_TARGETS) \
                       --disable-virtfs              \
                       --disable-xen                 \
                       --disable-bluez               \
                       --disable-vde                 \
                       --disable-libiscsi            \
                       --disable-docs                \
                       --disable-spice               \
                       $(EXTRA_QEMU_FLAGS)

QEMU_DEBUG_FLAGS = --enable-debug

QEMU_RELEASE_FLAGS =

stamps/qemu-debug-configure: export CFLAGS:=$(CFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: CONFIGURE_COMMAND = $(S2ESRC)/qemu/configure   \
                                                 $(QEMU_CONFIGURE_FLAGS)    \
                                                 $(QEMU_DEBUG_FLAGS)

stamps/qemu-debug-make:  stamps/qemu-debug-configure
	$(MAKE) -C qemu-debug $(BUILD_OPTS) install
	touch $@

##########
# libs2e #
##########

LIBS2E_CONFIGURE_FLAGS = --with-cc=$(CLANG_CC)                                      \
                         --with-cxx=$(CLANG_CXX)                                    \
                         --with-cflags=$(CFLAGS_ARCH)                               \
                         --with-cxxflags=$(CXXFLAGS_ARCH)                           \
                         --with-liblua=$(S2EBUILD)/$(LUA_DIR)/src                   \
                         --with-z3-incdir=$(S2EPREFIX)/include                      \
                         --with-z3-libdir=$(S2EPREFIX)/lib                          \
                         --with-libtcg-src=$(S2ESRC)/libtcg                         \
                         --with-libcpu-src=$(S2ESRC)/libcpu                         \
                         --with-libs2ecore-src=$(S2ESRC)/libs2ecore                 \
                         --with-libs2eplugins-src=$(S2ESRC)/libs2eplugins           \
                         --with-s2e-guest-incdir=$(S2ESRC)/libs2e/include     
                         $(EXTRA_QEMU_FLAGS)
LIBS2E_DEBUG_FLAGS = --with-llvm=$(LLVMBUILD)/llvm-debug                            \
                     --with-klee=$(S2EBUILD)/klee-debug                             \
                     --with-libvmi=$(S2EBUILD)/libvmi-debug                         \
                     --with-fsigc++=$(S2EBUILD)/libfsigc++-debug                    \
                     --with-libq=$(S2EBUILD)/libq-debug                             \
                     --enable-debug
stamps/libs2e-debug-configure: stamps/lua-make stamps/libvmi-debug-make        \
    stamps/klee-debug-make stamps/libfsigc++-debug-make        \
    stamps/libq-debug-make 
stamps/libs2e-debug-configure: CONFIGURE_COMMAND = $(S2ESRC)/libs2e/configure   \
                                                   $(LIBS2E_CONFIGURE_FLAGS)    \
                                                   $(LIBS2E_DEBUG_FLAGS)

stamps/libs2e-debug-make:  stamps/libs2e-debug-configure

