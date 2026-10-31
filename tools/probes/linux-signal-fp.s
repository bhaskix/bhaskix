        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0094 step 0: **whether a caught signal gives the interrupted code
        # its vector registers back.** Linux's frame carries them (`fpstate`)
        # and `rt_sigreturn` restores them, so a handler may use any register it
        # likes. Until step 3 this system's frame carried the general-purpose
        # registers only, and this probe is the defect shown rather than argued:
        # it holds a pattern in every `xmm` register, faults on purpose, and its
        # handler overwrites all sixteen before returning. The code it returns to
        # then checks its own.
        #
        # **And a handler's edit to the frame must stick**: the handler writes a
        # new `xmm15` into the image `uc_mcontext.fpstate` names, and the code
        # it returns to must find that value there -- the frame is what
        # `rt_sigreturn` restores, not a copy of something else.
        #
        # The page: word 0 one once resumed, word 1 the quadwords that came back
        # wrong, word 2 the last wrong value, word 3 what the handler found in
        # `xmm0` on entry -- zero where a handler starts from the initial state,
        # as Linux's does -- word 4 one once done, word 5 one if the frame had
        # an image to edit, and word 6 one if the upper halves were checked.
        # Bytes 64..320 are where the registers are stored to be compared --
        # xmm15 must hold the edited value -- and 320..576 their upper halves.
_start:
        mov     %rdi, %r15              # the report page

        # rt_sigaction(SIGSEGV, {handler, SA_SIGINFO|SA_RESTORER, restorer, 0})
        push    $0                      # sa_mask
        lea     restorer(%rip), %rax
        push    %rax                    # sa_restorer
        mov     $0x04000004, %eax       # SA_SIGINFO | SA_RESTORER
        push    %rax                    # sa_flags
        lea     handler(%rip), %rax
        push    %rax                    # sa_handler
        mov     %rsp, %rsi              # act
        mov     $11, %edi               # SIGSEGV
        xor     %edx, %edx              # no oldact
        mov     $8, %r10d               # sigsetsize
        mov     $13, %eax               # rt_sigaction
        syscall

        # xmmN := 0x5a5a5a5a00000000 + N, in both halves.
        mov     $0x5a5a5a5a00000000, %rax
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

        # **And the upper halves of ymm0-ymm15, where AVX is on** -- RFC 0094
        # step 4. Asked of the CPU, as the vector probe asks it; rbp carries
        # the answer, because a delivery leaves the registers it does not name
        # as they were and rt_sigreturn puts them back. Word 6 records it.
        xor     %ebp, %ebp
        mov     $1, %eax
        cpuid                           # clobbers rbx, rcx, rdx
        bt      $27, %ecx               # OSXSAVE
        jnc     6f
        xor     %ecx, %ecx
        xgetbv
        and     $6, %eax
        cmp     $6, %eax
        jne     6f
        mov     $1, %ebp
        movq    $1, 48(%r15)
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
6:
        # The fault: 0x10, inside the null page, which is never mapped.
        xor     %eax, %eax
        mov     0x10(%rax), %rax        # 4 bytes; the handler steps over them

        movq    $1, (%r15)              # resumed
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

        lea     64(%r15), %rsi
        mov     $0x5a5a5a5a00000000, %rax
        mov     $15, %ecx               # xmm0..xmm14 hold the pattern
        xor     %r12d, %r12d
check:
        mov     (%rsi), %rdx
        cmp     %rax, %rdx
        je      1f
        inc     %r12
        mov     %rdx, 16(%r15)
1:
        mov     8(%rsi), %rdx
        cmp     %rax, %rdx
        je      2f
        inc     %r12
        mov     %rdx, 16(%r15)
2:
        add     $16, %rsi
        inc     %rax
        dec     %ecx
        jnz     check
        # xmm15 holds what the handler wrote into the frame.
        mov     $0x7e7e7e7e7e7e7e7e, %rax
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
        # The upper halves came back as they were: each a copy of what its
        # register held before the fault, xmm15's included -- the handler
        # edited only the legacy half of ymm15 in the frame.
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
        mov     $0x5a5a5a5a00000000, %rax
        mov     $16, %ecx
upper:
        mov     (%rsi), %rdx
        cmp     %rax, %rdx
        je      8f
        inc     %r12
        mov     %rdx, 16(%r15)
8:
        mov     8(%rsi), %rdx
        cmp     %rax, %rdx
        je      9f
        inc     %r12
        mov     %rdx, 16(%r15)
9:
        add     $16, %rsi
        inc     %rax
        dec     %ecx
        jnz     upper
7:
        mov     %r12, 8(%r15)
        movq    $1, 32(%r15)            # done
done:
        jmp     done

        # rdx = the ucontext. r15 is still the report page: a delivery leaves
        # the registers it does not name as the fault left them.
handler:
        movq    %xmm0, %rax             # what this handler was given
        mov     %rax, 24(%r15)
        # The edit: a new xmm15, written into the frame's image. fpstate is
        # uc_mcontext's word at 184, ucontext 0xe0 (glibc's fpregs); xmm15 is
        # at 160 + 15 * 16 = 400 in the legacy region either layout shares.
        mov     0xe0(%rdx), %rcx
        test    %rcx, %rcx
        jz      5f
        movq    $1, 40(%r15)            # there was an image to edit
        mov     $0x7e7e7e7e7e7e7e7e, %rax
        mov     %rax, 400(%rcx)
        mov     %rax, 408(%rcx)
5:
        pcmpeqd %xmm0, %xmm0            # and every register overwritten
        pcmpeqd %xmm1, %xmm1
        pcmpeqd %xmm2, %xmm2
        pcmpeqd %xmm3, %xmm3
        pcmpeqd %xmm4, %xmm4
        pcmpeqd %xmm5, %xmm5
        pcmpeqd %xmm6, %xmm6
        pcmpeqd %xmm7, %xmm7
        pcmpeqd %xmm8, %xmm8
        pcmpeqd %xmm9, %xmm9
        pcmpeqd %xmm10, %xmm10
        pcmpeqd %xmm11, %xmm11
        pcmpeqd %xmm12, %xmm12
        pcmpeqd %xmm13, %xmm13
        pcmpeqd %xmm14, %xmm14
        pcmpeqd %xmm15, %xmm15
        # And every upper half, where AVX is on: xmm0 is all ones now.
        test    %rbp, %rbp
        jz      10f
        vinsertf128 $1, %xmm0, %ymm0, %ymm0
        vinsertf128 $1, %xmm0, %ymm1, %ymm1
        vinsertf128 $1, %xmm0, %ymm2, %ymm2
        vinsertf128 $1, %xmm0, %ymm3, %ymm3
        vinsertf128 $1, %xmm0, %ymm4, %ymm4
        vinsertf128 $1, %xmm0, %ymm5, %ymm5
        vinsertf128 $1, %xmm0, %ymm6, %ymm6
        vinsertf128 $1, %xmm0, %ymm7, %ymm7
        vinsertf128 $1, %xmm0, %ymm8, %ymm8
        vinsertf128 $1, %xmm0, %ymm9, %ymm9
        vinsertf128 $1, %xmm0, %ymm10, %ymm10
        vinsertf128 $1, %xmm0, %ymm11, %ymm11
        vinsertf128 $1, %xmm0, %ymm12, %ymm12
        vinsertf128 $1, %xmm0, %ymm13, %ymm13
        vinsertf128 $1, %xmm0, %ymm14, %ymm14
        vinsertf128 $1, %xmm0, %ymm15, %ymm15
10:
        mov     0xa8(%rdx), %rax        # the saved rip (glibc's REG_RIP)
        add     $4, %rax                # past the faulting mov
        mov     %rax, 0xa8(%rdx)
        ret                             # into the restorer

restorer:
        mov     $15, %eax               # rt_sigreturn
        syscall
        jmp     restorer
