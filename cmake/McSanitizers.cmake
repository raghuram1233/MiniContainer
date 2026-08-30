# Sanitizer support for minicontainer targets.
#
# IMPORTANT: never call mc_apply_sanitizers(mc_child). Code that runs between
# clone() and execve() must not allocate; ASan/UBSan instrumentation adds
# allocations and signal handlers that can deadlock or misbehave in that
# window (see the header comment in include/minicontainer/errors.h). The root
# CMakeLists.txt only applies this to mc_core, minicontainer, and the test
# binaries - mc_child is left uninstrumented on purpose.

function(mc_apply_sanitizers target)
  if(NOT MC_ENABLE_ASAN AND NOT MC_ENABLE_UBSAN)
    return()
  endif()

  set(_mc_saneflags "")
  if(MC_ENABLE_ASAN)
    list(APPEND _mc_saneflags -fsanitize=address)
  endif()
  if(MC_ENABLE_UBSAN)
    list(APPEND _mc_saneflags -fsanitize=undefined)
  endif()

  target_compile_options(${target} PRIVATE ${_mc_saneflags} -fno-omit-frame-pointer -g)
  target_link_options(${target} PRIVATE ${_mc_saneflags})
endfunction()
