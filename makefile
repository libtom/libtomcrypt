# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver
#
#  (GNU make only)

ifeq ($V,1)
silent=
silent_stdout=
else
silent=@
silent_stdout= > /dev/null
endif

PLATFORM := $(shell uname | sed -e 's/_.*//')

ifneq ($(MAKECMDGOALS),clean)
ifeq ($(PLATFORM), Darwin)
$(error Known to not work on Mac, please use makefile.unix for static libraries or makefile.shared for shared libraries)
endif
endif

# ranlib tools
ifndef RANLIB
RANLIB:=$(CROSS_COMPILE)ranlib
endif
INSTALL_CMD = install
UNINSTALL_CMD = rm

#Output filenames for various targets.
ifndef LIBNAME
   LIBNAME=libtomcrypt.a
endif


include makefile_include.mk

ifeq ($(COVERAGE),1)
all_test: LIB_PRE = -Wl,--whole-archive
all_test: LIB_POST = -Wl,--no-whole-archive
LTC_CFLAGS += -fprofile-arcs -ftest-coverage
EXTRALIBS += -lgcov
endif

#AES comes in two flavours... enc+dec and enc
src/ciphers/aes/aes_enc.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
	${silent} ${CC} ${LTC_CFLAGS} -DENCRYPT_ONLY -c $< -o $@

.c.o:
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} ${CC} ${LTC_CFLAGS} -c $< -o $@

$(LIBNAME): $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${AR} $@"
endif
	${silent} $(AR) $(ARFLAGS) $@ $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${RANLIB} $@"
endif
	${silent} $(RANLIB) $@

test: $(LIBNAME) $(TOBJECTS)
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} $(CC) $(LTC_LDFLAGS) $(TOBJECTS) $(LIB_PRE) $(LIBNAME) $(LIB_POST) $(EXTRALIBS) -o $(TEST)

# build the demos from a template
define DEMO_template
$(1): demos/$(1).o $$(LIBNAME)
ifneq ($V,1)
	@echo "   * $${CC} $$@"
endif
	$${silent} $$(CC) $$(LTC_CFLAGS) $$< $$(LIB_PRE) $$(LIBNAME) $$(LIB_POST) $$(EXTRALIBS) -o $(1)
endef

$(foreach demo, $(strip $(DEMOS)), $(eval $(call DEMO_template,$(demo))))


#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
install: .common_install

install_bins: .common_install_bins

uninstall: .common_uninstall

profile:
	LTC_CFLAGS="$(LTC_CFLAGS) -fprofile-generate" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"
	./timing
	rm -f timing `find . -type f | grep [.][ao] | xargs`
	LTC_CFLAGS="$(LTC_CFLAGS) -fprofile-use" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"

# target that pre-processes all coverage data
lcov-single-create:
	lcov --capture --no-external --directory src -q --output-file coverage_std.info

# target that removes all coverage output
cleancov-clean:
	rm -f `find . -type f -name "*.info" | xargs`
	rm -rf coverage/

# merges all coverage_*.info files into coverage.info
coverage.info:
	lcov `find -name 'coverage_*.info' -exec echo -n " -a {}" \;` -o coverage.info

# generates html output from all coverage_*.info files
lcov-html: coverage.info
	genhtml coverage.info --output-directory coverage -q

# combines all necessary steps to create the coverage from a single testrun with e.g.
# CFLAGS="-DUSE_LTM -DLTM_DESC -I../libtommath" EXTRALIBS="../libtommath/libtommath.a" make coverage -j9
lcov-single:
	$(MAKE) cleancov-clean
	$(MAKE) lcov-single-create
	$(MAKE) coverage.info


#make the code coverage of the library
coverage: LTC_CFLAGS += -fprofile-arcs -ftest-coverage
coverage: EXTRALIBS += -lgcov
coverage: LIB_PRE = -Wl,--whole-archive
coverage: LIB_POST = -Wl,--no-whole-archive

coverage: test
	./test

# cleans everything - coverage output and standard 'clean'
cleancov: cleancov-clean clean

# ref:         $Format:%D$
# git commit:  $Format:%H$
# commit time: $Format:%ai$
