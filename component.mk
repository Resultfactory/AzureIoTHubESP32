#
# Component Makefile
#
# (Uses default behaviour of compiling all source files in directory, adding 'include' to include path.)

COMPONENT_EMBED_TXTFILES := azure_root_cert.pem

CFLAGS += -Wno-error=switch -Wno-error=char-subscripts -Wno-error=sequence-point -Wno-error=unused-value -Wno-error=enum-compare
CXXFLAGS += -Wno-error=switch -Wno-error=char-subscripts -Wno-error=sequence-point -Wno-error=unused-value -Wno-error=enum-compare
