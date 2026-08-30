# Shared warning flags for minicontainer targets.
#
# -Werror is deliberately gated behind MC_WERROR (default OFF): five agents
# compile in parallel against each other's in-progress modules, and a stray
# warning in someone else's not-yet-finished file must not block your build.
# Turn MC_WERROR ON locally or in CI once the tree has stabilised.

function(mc_apply_warnings target)
  target_compile_options(${target} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wnon-virtual-dtor
  )
  if(MC_WERROR)
    target_compile_options(${target} PRIVATE -Werror)
  endif()
endfunction()
