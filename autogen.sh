#!/bin/sh

which autoreconf >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
   echo "ERROR: Failed to locate 'autoreconf'.  You may need to install autoconf + automake packages."
   exit -1
fi
autoreconf -i
if [[ $? -ne 0 ]]; then
   echo "ERROR: Failed to run 'autoreconf'."
   exit -1
fi

echo
echo "Build system has been initialized"
echo
echo "The following is a common process for completing installation:"
echo " -- Create a copy of 'env-example', edit the 'INSTALL' "
echo "    variable of that file to an appropriate location, "
echo "    then source that edited file."
echo " -- Run: './configure --prefix=\"\$INSTALL\"'"
echo " -- Run: 'make install'"
echo
