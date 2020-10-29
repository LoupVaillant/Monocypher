# Makefile template for Frama-C/Eva case studies.
# For details and usage information, see the Frama-C User Manual.

### Prologue. Do not modify this block. #######################################
-include path.mk
FRAMAC ?= frama-c
include $(shell $(FRAMAC)-config -scripts)/prologue.mk
###############################################################################

# Edit below as needed. MACHDEP is mandatory. Suggested flags are optional.

MACHDEP = x86_64

## Preprocessing flags (for -cpp-extra-args)
CPPFLAGS    += \
  -I../src \
  -I../src/optional \

## General flags
FCFLAGS     += \
  -add-symbolic-path=..:. \
  -kernel-warn-key annot:missing-spec=abort \
  -kernel-warn-key typing:implicit-function-declaration=abort \
  -no-warn-signed-overflow \

## Eva-specific flags
EVAFLAGS    += \
  -eva-warn-key builtins:missing-spec=abort \

## GUI-only flags
FCGUIFLAGS += \
  -add-symbolic-path=.:.. \

## Analysis targets (suffixed with .eva)
TARGETS = monocypher.eva

### Each target <t>.eva needs a rule <t>.parse with source files as prerequisites
monocypher.parse: \
  $(sort $(wildcard ../src/*.c)) \
  $(sort $(wildcard ../src/optional/*.c)) \
  ../tests/test-no-vectors.c \
  ../tests/utils.c \

### Epilogue. Do not modify this block. #######################################
include $(shell $(FRAMAC)-config -scripts)/epilogue.mk
###############################################################################

