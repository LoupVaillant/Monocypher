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
rsync -ad --exclude-from=tarball_ignore ./ $FOLDER

# Replace version markers by the actual version number (from tags)
for file in `find monocypher-$VERSION -type f`
do
    sed -i "s/__git__/$VERSION/g" $file
done

# Remove the dist target from the makefile (no recursive releases!)
sed '/dist:/,$d' makefile > $FOLDER/makefile

# Remove contributor notes from the README
sed '/Contributor notes/,$d' README.md > $FOLDER/README.md

# Make the actual tarball
tar -cvzf $TARBALL $FOLDER

# Remove the temporary folder
rm -rf $FOLDER
