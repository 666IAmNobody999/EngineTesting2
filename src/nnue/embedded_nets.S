/*
  Embedded NNUE networks (Android and Windows builds).

  Assembled into the binary only when NNUE_EMBEDDING is defined, i.e. with the
  Makefile option embed=yes (the default for COMP=ndk and Windows). The .incbin paths are
  relative to the make working directory (src/, or temp_builds/<arch>/ for the
  slices of a universal build, where the nets are symlinked).

  Every other target gets an empty object file.
*/

#if defined(NNUE_EMBEDDING) && defined(__ELF__)

    .section .rodata.pikafish_nets, "a", %progbits

    .balign 64
    .globl  pikafish_embedded_net_main
    .globl  pikafish_embedded_net_main_end
    .hidden pikafish_embedded_net_main
    .hidden pikafish_embedded_net_main_end
pikafish_embedded_net_main:
    .incbin "pikafish.nnue"
pikafish_embedded_net_main_end:

    .balign 64
    .globl  pikafish_embedded_net_zero
    .globl  pikafish_embedded_net_zero_end
    .hidden pikafish_embedded_net_zero
    .hidden pikafish_embedded_net_zero_end
pikafish_embedded_net_zero:
    .incbin "pikafish_zero_test.nnue"
pikafish_embedded_net_zero_end:

#elif defined(NNUE_EMBEDDING) && defined(_WIN32)

// Windows (PE/COFF): read-only data section; COFF has no .hidden. x86-64 and
// ARM64 Windows symbols carry no leading underscore, 32-bit x86 does.
    #if defined(__i386__)
        #define NET_SYM(x) _##x
    #else
        #define NET_SYM(x) x
    #endif

    .section .rdata$pikafish_nets, "dr"

    .balign 64
    .globl  NET_SYM(pikafish_embedded_net_main)
    .globl  NET_SYM(pikafish_embedded_net_main_end)
NET_SYM(pikafish_embedded_net_main):
    .incbin "pikafish.nnue"
NET_SYM(pikafish_embedded_net_main_end):

    .balign 64
    .globl  NET_SYM(pikafish_embedded_net_zero)
    .globl  NET_SYM(pikafish_embedded_net_zero_end)
NET_SYM(pikafish_embedded_net_zero):
    .incbin "pikafish_zero_test.nnue"
NET_SYM(pikafish_embedded_net_zero_end):

#endif

#if defined(__ELF__)
    .section .note.GNU-stack, "", %progbits
#endif
