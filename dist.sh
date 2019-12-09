#! /bin/sh

set -e

VERSION=`git describe --tags`
FOLDER=monocypher-$VERSION
TARBALL=$FOLDER.tar.gz

# Run the tests before we do anything.  It's not enough (we ought to run
# the tests from the tarball itself, including the TIS interpreter), but
# it should prevent the most egregious errors.
tests/test.sh

# Generate documentation for users who don't have mandoc
doc/man2html.sh

# Delete the destination folder just to make sure everything is clean.
# May be needed if we unpack the tarball in place for testing purposes,
# then run the release script again.
rm -rf $FOLDER

# copy everything except ignored files to the
rsync -ad --exclude-from=dist_ignore ./ $FOLDER

# Replace version markers by the actual version number (from tags)
find $FOLDER -type f -exec sed -i "s/__git__/$VERSION/g" \{\} \;

# Remove the dist target from the makefile (no recursive releases!),
# and the tests/vector.h target, which ships with the tarball.
sed -i '/tests\/vectors.h:/,$d' $FOLDER/makefile

# Remove contributor notes from the README
sed -i '/Contributor notes/,$d' $FOLDER/README.md

# Make the actual tarball
tar -cvzf $TARBALL $FOLDER

# Remove the temporary folder
rm -rf $FOLDER
