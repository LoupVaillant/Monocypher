#! /bin/sh

echo
echo "Build"
echo "====="
make self sodium donna

echo
echo "Self contained tests"
echo "===================="
./self
retval_test=$?

echo
echo "Random comparison tests with libsodium"
echo "======================================"
./sodium
retval_sodium=$?

echo
echo "Random comparison tests with ed25519-donna)"
echo "==========================================="
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
    echo "==================="
    echo "== All tests OK! =="
    echo "==================="
    echo ""
fi
