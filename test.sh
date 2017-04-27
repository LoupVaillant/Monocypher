#! /bin/sh

echo
echo "Build"
echo "-----"
make test sodium donna

echo
echo "Independent tests (with vectors)"
echo "--------------------------------"
./test
retval_test=$?

echo
echo "Fuzz tests (compare with libsodium)"
echo "-----------------------------------"
./sodium
retval_sodium=$?
echo
echo "Fuzz tests (compare with ed25519-donna)"
echo "---------------------------------------"
./donna
retval_donna=$?

echo
if [ "$retval_test"   -ne 0 ] ||\
   [ "$retval_sodium" -ne 0 ] ||\
   [ "$retval_donna"  -ne 0 ]
then
    echo "TESTS FAILED.  VERIFY IMPLEMENTATION.  REPORT BUG"
    echo "DO. NOT. USE."
else
    echo "All tests OK!"
fi
