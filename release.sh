#! /bin/sh

set -e

VERSION=`git describe --tags`

doc/man2html.sh
rsync -avd --exclude-from=tarball_ignore ./ monocypher-$VERSION
for file in `find monocypher-$VERSION -type f `
do
    sed -i "s/__git__/$VERSION/g" $file
done
tar -czf monocypher-$VERSION.tar.gz monocypher-$VERSION
rm -rf monocypher-$VERSION
