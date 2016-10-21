AC_DEFUN([AXATTR_CHECK], dnl Checks for the proper configuration of xattr headers and C funciton calls
   [AC_CHECK_HEADER([sys/xattr.h], 
      [AC_DEFINE([AXATTR_RES], [1], [1='Apple/Linux with sys/xattr.h', 2='Linux with attr/xattr.h'])], 
      [AC_CHECK_HEADER([attr/xattr.h], 
         [AC_DEFINE([AXATTR_RES], [2], [1='Apple/Linux with sys/xattr.h', 2='Linux with attr/xattr.h'])], 
         [AC_MSG_ERROR([Could not locate <sys/xattr.h> nor <attr/xattr.h> for this Linux system])])])])

AC_DEFUN([AXATTR_GET_FUNC_CHECK],
   [AC_LANG([C])
   AC_COMPILE_IFELSE([dnl Performs compilation tests with various xattr function formats
      AC_LANG_PROGRAM([[
      #if (AXATTR_RES == 1)
      #   include <sys/xattr.h>
      #else
      #   include <attr/xattr.h>
      #endif
      char xattrval[20];
      ]], [[
      getxattr("test","user.test",&xattrval[0],sizeof(xattrval));
      ]])], 
      [AC_DEFINE([AXATTR_GET_FUNC], [4], [Arg cnt for getxattr()])], 
      [AC_COMPILE_IFELSE([dnl Performs compilation tests with various xattr function formats
         AC_LANG_PROGRAM([[
         #if (AXATTR_RES == 1)
         #   include <sys/xattr.h>
         #else
         #   include <attr/xattr.h>
         #endif
         char xattrval[20];
         ]], [[
         getxattr("test","user.test",&xattrval[0],sizeof(xattrval),0);
         ]])], 
         [AC_DEFINE([AXATTR_GET_FUNC], [5], [Arg cnt for getxattr()])], 
         [AC_MSG_ERROR([Could not identify a getxattr() function on this system])])])])

