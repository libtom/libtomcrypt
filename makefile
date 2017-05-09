# MAKEFILE for linux GCC
#
# Tom St Denis
# Modified by Clay Culver

include makefile.include

ifeq ($V,1)
silent=
silent_stdout=
else
silent=@
silent_stdout= > /dev/null
endif

# ranlib tools
ifndef RANLIB
ifeq ($(PLATFORM), Darwin)
RANLIB:=$(PREFIX)ranlib -c
else
RANLIB:=$(PREFIX)ranlib
endif
endif
INSTALL_CMD = install


#Output filenames for various targets.
ifndef LIBNAME
   LIBNAME=libtomcrypt.a
endif
ifndef LIBTEST
   LIBTEST=libtomcrypt_prof.a
endif

#AES comes in two flavours... enc+dec and enc
src/ciphers/aes/aes_enc.o: src/ciphers/aes/aes.c src/ciphers/aes/aes_tab.c
	${silent} ${CC} ${CFLAGS} -DENCRYPT_ONLY -c $< -o $@

.c.o:
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} ${CC} ${CFLAGS} -c $< -o $@

$(LIBNAME): $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${AR} $@"
endif
	${silent} $(AR) $(ARFLAGS) $@ $(OBJECTS)
ifneq ($V,1)
	@echo "   * ${RANLIB} $@"
endif
	${silent} $(RANLIB) $@

$(LIBTEST): $(TOBJECTS)
ifneq ($V,1)
	@echo "   * ${AR} $@"
endif
	${silent} $(AR) $(ARFLAGS) $@ $(TOBJECTS)
ifneq ($V,1)
	@echo "   * ${RANLIB} $@"
endif
	${silent} $(RANLIB) $@

timing: $(LIBNAME) $(LIBTEST) $(TIMINGS)
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} $(CC) $(LDFLAGS) $(TIMINGS) $(LIBTEST) $(LIB_PRE) $(LIBNAME) $(LIB_POST) $(EXTRALIBS) -o $(TIMING)

test: $(LIBNAME) $(LIBTEST) $(TESTS)
ifneq ($V,1)
	@echo "   * ${CC} $@"
endif
	${silent} $(CC) $(LDFLAGS) $(TESTS) $(LIBTEST) $(LIB_PRE) $(LIBNAME) $(LIB_POST) $(EXTRALIBS) -o $(TEST)

# build the demos from a template
define DEMO_template
$(1): demos/$(1).o $$(LIBNAME)
ifneq ($V,1)
	@echo "   * $${CC} $$@"
endif
	$${silent} $$(CC) $$(CFLAGS) $$< $$(LIB_PRE) $$(LIBNAME) $$(LIB_POST) $$(EXTRALIBS) -o $(1)
endef

$(foreach demo, $(strip $(DEMOS)), $(eval $(call DEMO_template,$(demo))))

ifeq ($(COVERAGE),1)
all_test: LIB_PRE = -Wl,--whole-archive
all_test: LIB_POST = -Wl,--no-whole-archive
endif

#This rule installs the library and the header files. This must be run
#as root in order to have a high enough permission to write to the correct
#directories and to set the owner and group to root.
install: .common_install

install_bins: .common_install_bins

install_test: .common_install_test

profile:
	CFLAGS="$(CFLAGS) -fprofile-generate" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"
	./timing
	rm -f timing `find . -type f | grep [.][ao] | xargs`
	CFLAGS="$(CFLAGS) -fprofile-use" $(MAKE) timing EXTRALIBS="$(EXTRALIBS) -lgcov"

# target that pre-processes all coverage data
lcov-single-create:
	lcov --capture --no-external --directory src -q --output-file coverage_std.info

# target that removes all coverage output
cleancov-clean:
	rm -f `find . -type f -name "*.info" | xargs`
	rm -rf coverage/

# generates html output from all coverage_*.info files
lcov:
	lcov `find -name 'coverage_*.info' -exec echo -n " -a {}" \;` -o coverage.info -q 2>/dev/null
	genhtml coverage.info --output-directory coverage -q

# combines all necessary steps to create the coverage from a single testrun with e.g.
# CFLAGS="-DUSE_LTM -DLTM_DESC -I../libtommath" EXTRALIBS="../libtommath/libtommath.a" make coverage -j9
lcov-single: | cleancov-clean lcov-single-create lcov


#make the code coverage of the library
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: EXTRALIBS += -lgcov
coverage: LIB_PRE = -Wl,--whole-archive
coverage: LIB_POST = -Wl,--no-whole-archive

coverage: test
	./test

# cleans everything - coverage output and standard 'clean'
cleancov: cleancov-clean clean

include makefile.common

# git commit: $Format:%h$ $Format:%ai$
