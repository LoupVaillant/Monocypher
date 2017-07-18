#! /bin/sh

# Parses the source code
frama-c formal-analysis/*.c -save parsed.sav

# Analyses the source code
frama-c -load parsed.sav -val-builtins-auto -val -save value.sav -no-val-show-progress -memexec-all

# Launches the Gui
frama-c-gui -load value.sav
