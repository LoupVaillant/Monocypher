#! /bin/sh

# Parses the source code
frama-c frama-c/*.c -cpp-extra-args="-DED25519_SHA512" -save parsed.sav

# Analyses the source code
frama-c -load parsed.sav -val-builtins-auto -val -save value.sav -no-val-show-progress -memexec-all

# Launches the Gui
frama-c-gui -load value.sav
