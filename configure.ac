# https://www.gnu.org/software/automake/manual/automake.html
# https://www.gnu.org/software/autoconf/manual/autoconf.html

AC_PREREQ([2.63])

AC_INIT([libtomcrypt],[1.18.1])
AC_SUBST([ABI_VERSION],[1:1:1])
AC_LANG([C])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(aux-dist)

AM_INIT_AUTOMAKE([1.11.1 no-define])
LT_PREREQ([2.2.6])
LT_INIT

AC_CONFIG_FILES([Makefile libtomcrypt.pc])

AC_MSG_CHECKING([for compiler warning level (--enable-warnings)])
AC_ARG_ENABLE([warnings],
  [AS_HELP_STRING([--enable-warnings[[=0-9]]],[Enable compiler warnings. DEFAULT=0 (for development use 3)])],
  [AS_CASE([$enableval],
    [yes],[wlevel=1],
    [no],[wlevel=0],
    [[[0-9]]],[wlevel="$enableval"],
    [wlevel=0]
  )],
  [wlevel=0])
AC_MSG_RESULT([$wlevel])
AS_CASE([$wlevel],
  [0],[WARNING_FLAGS=""],
  [1],[WARNING_FLAGS="-Wall"],
  [2],[WARNING_FLAGS="-Wall -Wextra"],
  [3],[WARNING_FLAGS="-Wall -Wextra -Werror"],
  # --enable-warnings=6 requires gcc v6
  [6],[WARNING_FLAGS="-Wall -Wextra -Werror -Wdeclaration-after-statement -Wmissing-declarations -Wmissing-prototypes -Wmissing-noreturn -Woverflow -Wnonnull -Wunused-const-variable -Wundef -Wshift-negative-value -Wshift-overflow -Wtautological-compare -Wmisleading-indentation -Woverride-init-side-effects -Wnonnull-compare -Wnull-dereference -Wwrite-strings -Wshadow -Wjump-misses-init -Wlogical-op -Wduplicated-cond -Wformat=2 -Wmaybe-uninitialized -Wunused-parameter -Wbad-function-cast -Wcast-align -Wchar-subscripts -Wcomment -Wfloat-equal -Wimplicit -Wnormalized=id -Woverride-init -Wparentheses -Wpointer-arith -Wstrict-prototypes"],
  # --enable-warnings=7 requires gcc v7
  [7],[WARNING_FLAGS="-Wall -Wextra -Werror -Wdeclaration-after-statement -Wimplicit-fallthrough -Wmissing-declarations -Wmissing-prototypes -Wmissing-noreturn -Woverflow -Wnonnull -Walloc-zero -Wdangling-else -Wswitch-unreachable -Wrestrict -Wduplicated-branches -Wpointer-compare -Wunused-const-variable -Wundef -Wshift-negative-value -Wshift-overflow -Wtautological-compare -Wmisleading-indentation -Woverride-init-side-effects -Wnonnull-compare -Wnull-dereference -Wwrite-strings -Wshadow -Wjump-misses-init -Wlogical-op -Wduplicated-cond -Wformat=2 -Wmaybe-uninitialized -Wunused-parameter -Wbad-function-cast -Wcast-align -Wchar-subscripts -Wcomment -Wfloat-equal -Wimplicit -Wnormalized=id -Woverride-init -Wparentheses -Wpointer-arith -Wstrict-prototypes"],
)
AC_SUBST(WARNING_FLAGS)

# Check for LTM
AC_MSG_CHECKING([whether to build libtomcrypt with libtommath (--with-ltm)])
AC_ARG_WITH([ltm],
  [AS_HELP_STRING(
    [--with-ltm[[=ARG]]],
    [Use libtommath to build libtomcrypt. Optional ARG is the libtommath installation prefix (if not given libtommath is detected via pkg-config). DEFAULT=enabled]
  )],
  [AS_CASE([$with_ltm],
    [yes],[with_ltm_result=yes],
    [no],[with_ltm_result=no],
    [with_ltm_result=yes;with_ltm_path="$with_ltm"]
  )],
  [with_ltm_result=yes]
)
AC_MSG_RESULT([$with_ltm_result])
AS_VAR_IF([with_ltm_result],[yes],[
  AS_VAR_SET_IF([with_ltm_path],
    [
      extra_inc="-I$with_ltm_path/include"
      extra_lib="-L$with_ltm_path/lib"
    ],
    [
      extra_inc=`pkg-config --cflags-only-I libtommath 2>/dev/null`
      extra_lib=`pkg-config --libs-only-L libtommath 2>/dev/null`
    ]
  )
  CPPFLAGS="$CPPFLAGS $extra_inc"
  LDFLAGS="$LDFLAGS $extra_lib"
  AC_CHECK_HEADER([tommath.h],[extra_cppflags="$extra_inc -DLTM_DESC"],[AC_MSG_ERROR([libtommath is not usable.])])
  AC_CHECK_LIB([tommath],[mp_add],[extra_ldflags="$extra_lib -ltommath"],[AC_MSG_ERROR([libtommath is not usable.])])
  CPPFLAGS="$temp_cppflags"
  LDFLAGS="$temp_ldflags"
  AC_SUBST([LTM_CPPFLAGS],[$extra_cppflags])
  AC_SUBST([LTM_LDFLAGS],[$extra_ldflags])
  AC_MSG_RESULT([         Build with ltm: yes])
  AC_MSG_RESULT([         LTM_CPPFLAGS=$extra_cppflags])
  AC_MSG_RESULT([         LTM_LDFLAGS=$extra_ldflags])
])

# Check for GMP
AC_MSG_CHECKING([whether to build libtomcrypt with GMP (--with-gmp)])
AC_ARG_WITH([gmp],
  [AS_HELP_STRING(
    [--with-gmp[[=ARG]]],
    [Use GMP to build libtomcrypt. Optional ARG is the GMP installation prefix (if not given GMP is detected via pkg-config). DEFAULT=disabled]
  )],
  [AS_CASE([$with_gmp],
    [yes],[with_gmp_result=yes],
    [no],[with_gmp_result=no],
    [with_gmp_result=yes;with_gmp_path="$with_gmp"]
  )],
  [with_gmp_result=no]
)
AC_MSG_RESULT([$with_gmp_result])
AS_VAR_IF([with_gmp_result],[yes],[
  AS_VAR_SET_IF([with_gmp_path],
    [
      extra_inc="-I$with_gmp_path/include"
      extra_lib="-L$with_gmp_path/lib"
    ],
    [
      extra_inc=`pkg-config --cflags-only-I gmp 2>/dev/null`
      extra_lib=`pkg-config --libs-only-L gmp 2>/dev/null`
    ]
  )
  CPPFLAGS="$CPPFLAGS $extra_inc"
  LDFLAGS="$LDFLAGS $extra_lib"
  AC_CHECK_HEADER([gmp.h],[extra_cppflags="$extra_inc -DGMP_DESC"],[AC_MSG_ERROR([gmp is not usable.])])
  AC_CHECK_LIB([gmp],[ __gmpz_init],[extra_ldflags="$extra_lib -lgmp"],[AC_MSG_ERROR([gmp is not usable.])])
  CPPFLAGS="$temp_cppflags"
  LDFLAGS="$temp_ldflags"
  AC_SUBST([GMP_CPPFLAGS],[$extra_cppflags])
  AC_SUBST([GMP_LDFLAGS],[$extra_ldflags])
  AC_MSG_RESULT([         Build with gmp: yes])
  AC_MSG_RESULT([         GMP_CPPFLAGS=$extra_cppflags])
  AC_MSG_RESULT([         GMP_LDFLAGS=$extra_ldflags])
])

# Check for TFM
AC_MSG_CHECKING([whether to build libtomcrypt with tomsfastmath (--with-tfm)])
AC_ARG_WITH([tfm],
  [AS_HELP_STRING(
    [--with-tfm[[=ARG]]],
    [Use tomsfastmath to build libtomcrypt. Optional ARG is the tfm installation prefix (if not given tfm is detected via pkg-config). DEFAULT=disabled]
  )],
  [AS_CASE([$with_tfm],
    [yes],[with_tfm_result=yes],
    [no],[with_tfm_result=no],
    [with_tfm_result=yes;with_tfm_path="$with_tfm"]
  )],
  [with_tfm_result=no]
)
AC_MSG_RESULT([$with_tfm_result])
AS_VAR_IF([with_tfm_result],[yes],[
  AS_VAR_SET_IF([with_tfm_path],
    [
      extra_inc="-I$with_tfm_path/include"
      extra_lib="-L$with_tfm_path/lib"
    ],
    [
      extra_inc=`pkg-config --cflags-only-I tomsfastmath 2>/dev/null`
      extra_lib=`pkg-config --libs-only-L tomsfastmath 2>/dev/null`
    ]
  )
  CPPFLAGS="$CPPFLAGS $extra_inc"
  LDFLAGS="$LDFLAGS $extra_lib"
  AC_CHECK_HEADER([tfm.h],[extra_cppflags="$extra_inc -DTFM_DESC"],[AC_MSG_ERROR([tomsfastmath is not usable.])])
  AC_CHECK_LIB([tfm],[fp_add],[extra_ldflags="$extra_lib -ltfm"],[AC_MSG_ERROR([tomsfastmath is not usable.])])
  CPPFLAGS="$temp_cppflags"
  LDFLAGS="$temp_ldflags"
  AC_SUBST([TFM_CPPFLAGS],[$extra_cppflags])
  AC_SUBST([TFM_LDFLAGS],[$extra_ldflags])
  AC_MSG_RESULT([         Build with ltm: yes])
  AC_MSG_RESULT([         TFM_CPPFLAGS=$extra_cppflags])
  AC_MSG_RESULT([         TFM_LDFLAGS=$extra_ldflags])
])

AC_ARG_WITH(tools,AC_HELP_STRING([--with-tools],[Build and install libtomcrypt tools. DEFAULT=disabled]),build_tools=$withval,build_tools=no)
AC_ARG_WITH(demos,AC_HELP_STRING([--with-demos],[Build libtomcrypt demos. DEFAULT=disabled]),build_demos=$withval,build_demos=no)

AM_CONDITIONAL([WITH_DEMOS],[test "x$build_demos" = "xyes"])
AM_CONDITIONAL([WITH_TOOLS],[test "x$build_tools" = "xyes"])

AM_CONDITIONAL([WITH_LTM],[test -n "$LTM_LDFLAGS"])
AM_CONDITIONAL([WITH_GMP],[test -n "$GMP_LDFLAGS"])
AM_CONDITIONAL([WITH_TFM],[test -n "$TFM_LDFLAGS"])

AM_CONDITIONAL([WITH_NOMATH],[test -z "$LTM_LDFLAGS$GMP_LDFLAGS$TFM_LDFLAGS"])

AC_MSG_RESULT([         Build demos: $build_demos])
AC_MSG_RESULT([         Build tools: $build_tools])

AC_OUTPUT
