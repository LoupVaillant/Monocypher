#! /bin/sh

echo
echo "Build"
echo "-----"
make vectors properties sodium donna

echo
echo "Tests against vectors"
echo "---------------------"
./vectors
retval_test=$?

echo
echo "Random self-consistency tests"
echo "-----------------------------"
./properties
retval_prop=$?

echo
echo "Random comparison tests with libsodium"
echo "--------------------------------------"
./sodium
retval_sodium=$?

echo
echo "Random comparison tests with ed25519-donna)"
echo "-------------------------------------------"
./donna
retval_donna=$?

echo
if [ "$retval_test"   -ne 0 ] ||\
   [ "$retval_prop"   -ne 0 ] ||\
   [ "$retval_sodium" -ne 0 ] ||\
   [ "$retval_donna"  -ne 0 ]
then
    echo "TESTS FAILED.  VERIFY IMPLEMENTATION.  REPORT BUG"
    echo "DO. NOT. USE."
else
    echo "-------------------"
    echo "-- All tests OK! --"
    echo "-------------------"
    echo ""
fi
