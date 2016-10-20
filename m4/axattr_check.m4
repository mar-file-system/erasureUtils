AC_DEFUN([AXATTR_CHECK], dnl Checks for the proper configuration of xattr headers and C funciton calls
   [AC_CHECK_HEADER([sys/xattr.h], 
      [AC_DEFINE([AXATTR_RES], [1], [1='Apple/Linux with sys/xattr.h', 2='Linux with attr/xattr.h'])], 
      [AC_CHECK_HEADER([attr/xattr.h], 
         [AC_DEFINE([AXATTR_RES], [2], [1='Apple/Linux with sys/xattr.h', 2='Linux with attr/xattr.h'])], 
         [AC_MSG_ERROR([Could not locate <sys/xattr.h> nor <attr/xattr.h> for this Linux system])])])])

