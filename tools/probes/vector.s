        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards; rsi = this
        # thread's seed.
        #
        # RFC 0094 step 0: **whether a thread's vector registers are its own.**
        # Two of these run in two domains pinned to one CPU, each holding its
        # own pattern in every `xmm` register, and yield to each other a
        # thousand times. A switch that did not save and restore the register
        # file would hand each the other's values -- silently, which is why it
        # is counted here rather than trusted. `CR4.OSFXSR` is the kernel's
        # promise that this cannot happen; this is the promise being checked.
        #
        # SSE2 only, so it runs on every lane, `qemu64` included.
        #
        # **And the upper halves of `ymm0`-`ymm15`, where AVX is on** -- RFC
        # 0094 step 4. Whether it is, the probe asks the CPU itself, as Go and
        # glibc do: `CPUID.1:ECX.OSXSAVE`, then `XGETBV` for x87|SSE|AVX. Where
        # it is, each register's pattern is copied into its upper half and the
        # upper halves are checked too. AVX1 instructions only (`vinsertf128`,
        # `vextractf128`): `XCR0` promises AVX, not AVX2.
        #
        # The page: word 0 the rounds completed, word 1 the quadwords that came
        # back wrong, word 2 the last wrong value seen, word 3 one once done,
        # word 4 one if the upper halves were checked. Bytes 64..320 are where
        # each round stores the sixteen registers to compare them -- in memory,
        # because comparing in a register would need a seventeenth -- and
        # 320..576 where it stores their upper halves.
_start:
        mov     %rdi, %r15              # the report page
        mov     %rsi, %r14              # the seed

        # xmmN := seed + N, in both halves.
        mov     %r14, %rax
        movq    %rax, %xmm0
        punpcklqdq %xmm0, %xmm0
        inc     %rax
        movq    %rax, %xmm1
        punpcklqdq %xmm1, %xmm1
        inc     %rax
        movq    %rax, %xmm2
        punpcklqdq %xmm2, %xmm2
        inc     %rax
        movq    %rax, %xmm3
        punpcklqdq %xmm3, %xmm3
        inc     %rax
        movq    %rax, %xmm4
        punpcklqdq %xmm4, %xmm4
        inc     %rax
        movq    %rax, %xmm5
        punpcklqdq %xmm5, %xmm5
        inc     %rax
        movq    %rax, %xmm6
        punpcklqdq %xmm6, %xmm6
        inc     %rax
        movq    %rax, %xmm7
        punpcklqdq %xmm7, %xmm7
        inc     %rax
        movq    %rax, %xmm8
        punpcklqdq %xmm8, %xmm8
        inc     %rax
        movq    %rax, %xmm9
        punpcklqdq %xmm9, %xmm9
        inc     %rax
        movq    %rax, %xmm10
        punpcklqdq %xmm10, %xmm10
        inc     %rax
        movq    %rax, %xmm11
        punpcklqdq %xmm11, %xmm11
        inc     %rax
        movq    %rax, %xmm12
        punpcklqdq %xmm12, %xmm12
        inc     %rax
        movq    %rax, %xmm13
        punpcklqdq %xmm13, %xmm13
        inc     %rax
        movq    %rax, %xmm14
        punpcklqdq %xmm14, %xmm14
        inc     %rax
        movq    %rax, %xmm15
        punpcklqdq %xmm15, %xmm15

        # Is AVX on? rbp says, for the rest of the probe: the system call
        # preserves it, and nothing else here uses it.
        xor     %ebp, %ebp
        mov     $1, %eax
        cpuid                           # clobbers rbx, rcx, rdx
        bt      $27, %ecx               # OSXSAVE
        jnc     6f
        xor     %ecx, %ecx
        xgetbv                          # XCR0 into edx:eax
        and     $6, %eax
        cmp     $6, %eax                # SSE and AVX both enabled
        jne     6f
        mov     $1, %ebp
        vinsertf128 $1, %xmm0, %ymm0, %ymm0
        vinsertf128 $1, %xmm1, %ymm1, %ymm1
        vinsertf128 $1, %xmm2, %ymm2, %ymm2
        vinsertf128 $1, %xmm3, %ymm3, %ymm3
        vinsertf128 $1, %xmm4, %ymm4, %ymm4
        vinsertf128 $1, %xmm5, %ymm5, %ymm5
        vinsertf128 $1, %xmm6, %ymm6, %ymm6
        vinsertf128 $1, %xmm7, %ymm7, %ymm7
        vinsertf128 $1, %xmm8, %ymm8, %ymm8
        vinsertf128 $1, %xmm9, %ymm9, %ymm9
        vinsertf128 $1, %xmm10, %ymm10, %ymm10
        vinsertf128 $1, %xmm11, %ymm11, %ymm11
        vinsertf128 $1, %xmm12, %ymm12, %ymm12
        vinsertf128 $1, %xmm13, %ymm13, %ymm13
        vinsertf128 $1, %xmm14, %ymm14, %ymm14
        vinsertf128 $1, %xmm15, %ymm15, %ymm15
        movq    $1, 32(%r15)            # word 4: the upper halves are checked
6:
        mov     $1000, %r13             # rounds to go
        xor     %r12d, %r12d            # wrong quadwords seen
round:
        mov     $4, %eax                # YIELD: the other thread runs now
        syscall

        movdqu  %xmm0, 64(%r15)
        movdqu  %xmm1, 80(%r15)
        movdqu  %xmm2, 96(%r15)
        movdqu  %xmm3, 112(%r15)
        movdqu  %xmm4, 128(%r15)
        movdqu  %xmm5, 144(%r15)
        movdqu  %xmm6, 160(%r15)
        movdqu  %xmm7, 176(%r15)
        movdqu  %xmm8, 192(%r15)
        movdqu  %xmm9, 208(%r15)
        movdqu  %xmm10, 224(%r15)
        movdqu  %xmm11, 240(%r15)
        movdqu  %xmm12, 256(%r15)
        movdqu  %xmm13, 272(%r15)
        movdqu  %xmm14, 288(%r15)
        movdqu  %xmm15, 304(%r15)

        lea     64(%r15), %rsi          # the stored registers
        mov     %r14, %rax              # what register 0 should hold
        mov     $16, %ecx               # registers to check
check:
        mov     (%rsi), %rdx            # the low quadword
        cmp     %rax, %rdx
        je      1f
        inc     %r12
        mov     %rdx, 16(%r15)
1:
        mov     8(%rsi), %rdx           # and the high one
        cmp     %rax, %rdx
        je      2f
        inc     %r12
        mov     %rdx, 16(%r15)
2:
        add     $16, %rsi
        inc     %rax
        dec     %ecx
        jnz     check

        # The upper halves, where they are being kept.
        test    %rbp, %rbp
        jz      7f
        vextractf128 $1, %ymm0, 320(%r15)
        vextractf128 $1, %ymm1, 336(%r15)
        vextractf128 $1, %ymm2, 352(%r15)
        vextractf128 $1, %ymm3, 368(%r15)
        vextractf128 $1, %ymm4, 384(%r15)
        vextractf128 $1, %ymm5, 400(%r15)
        vextractf128 $1, %ymm6, 416(%r15)
        vextractf128 $1, %ymm7, 432(%r15)
        vextractf128 $1, %ymm8, 448(%r15)
        vextractf128 $1, %ymm9, 464(%r15)
        vextractf128 $1, %ymm10, 480(%r15)
        vextractf128 $1, %ymm11, 496(%r15)
        vextractf128 $1, %ymm12, 512(%r15)
        vextractf128 $1, %ymm13, 528(%r15)
        vextractf128 $1, %ymm14, 544(%r15)
        vextractf128 $1, %ymm15, 560(%r15)
        lea     320(%r15), %rsi
        mov     %r14, %rax
        mov     $16, %ecx
upper:
        mov     (%rsi), %rdx
        cmp     %rax, %rdx
        je      3f
        inc     %r12
        mov     %rdx, 16(%r15)
3:
        mov     8(%rsi), %rdx
        cmp     %rax, %rdx
        je      4f
        inc     %r12
        mov     %rdx, 16(%r15)
4:
        add     $16, %rsi
        inc     %rax
        dec     %ecx
        jnz     upper
7:
        incq    (%r15)                  # one more round, whatever it found
        mov     %r12, 8(%r15)
        dec     %r13
        jnz     round

        movq    $1, 24(%r15)            # done
done:
        mov     $4, %eax                # and out of the other thread's way
        syscall
        jmp     done
