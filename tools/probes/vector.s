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
        # The page: word 0 the rounds completed, word 1 the quadwords that came
        # back wrong, word 2 the last wrong value seen, word 3 one once done.
        # Bytes 64..320 are where each round stores the sixteen registers to
        # compare them -- in memory, because comparing in a register would need
        # a seventeenth.
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

        incq    (%r15)                  # one more round, whatever it found
        mov     %r12, 8(%r15)
        dec     %r13
        jnz     round

        movq    $1, 24(%r15)            # done
done:
        mov     $4, %eax                # and out of the other thread's way
        syscall
        jmp     done
