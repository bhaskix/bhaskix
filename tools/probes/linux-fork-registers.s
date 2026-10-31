        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0096: **a forked child starts with its parent's registers.** A
        # Linux `syscall` changes `rax`, `rcx` and `r11` and nothing else, and
        # glibc's inline `fork` tells the compiler exactly that -- so any other
        # register may hold a live value across the call, in the child as in
        # the parent. Until this RFC a child here started on a three-instruction
        # trampoline with every register but `rax`, `rip` and `rsp` zero, and
        # its floating-point state and TLS base the kernel's initial ones.
        #
        # So the parent sets twelve general registers, all sixteen `xmm`
        # registers, `MXCSR` and its TLS base to values nothing else would
        # produce, and forks (57). The child counts every one that arrived as
        # anything else, and the stack word the parent left at `rsp`, and exits
        # with the count; the parent collects it with `wait4`.
        #
        # **Then glibc's own shape**: `clone(CLONE_CHILD_SETTID |
        # CLONE_CHILD_CLEARTID | SIGCHLD)` with no stack, the call `fork()` in a
        # static glibc program makes. Its child checks that its tid is its pid,
        # that the tid word it named holds that number in its own memory, and
        # that the two argument registers `clone` read came back as they went
        # in; the parent checks that its own copy of the word was not written.
        #
        # The page: word 0 one once done; word 1 the fork child's wait status,
        # word 2 the pid `fork` answered, word 3 the pid `wait4` collected; word
        # 4 the clone child's wait status, word 5 the pid `clone` answered, word
        # 6 the pid `wait4` collected; word 7 the tid word, as the parent's
        # copy holds it afterwards (-1 before, and it must stay -1).
        #
        # A child's exit status is its count of wrong values: 47 at most
        # (twelve registers, the stack word, the TLS witness, 32 quadwords and
        # `MXCSR`), so it fits the status byte.
_start:
        mov     %rdi, %r15              # the report page
        push    %rdi                    # 8(%rsp): the report page, across the fork
        mov     $0x7e57f5ba5e000001, %rax
        push    %rax                    # (%rsp): the witness, read through %fs and at rsp

        # arch_prctl(ARCH_SET_FS, rsp): the TLS base is the witness's address.
        mov     $158, %eax
        mov     $0x1002, %edi
        mov     %rsp, %rsi
        syscall

        # MXCSR: every exception masked, round toward zero, flush to zero --
        # 0xff80, where the initial state is 0x1f80.
        sub     $16, %rsp
        movl    $0xff80, (%rsp)
        ldmxcsr (%rsp)
        add     $16, %rsp

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

        # Twelve general registers: 0x6b6b6b6b00000000 + 1..12.
        mov     $0x6b6b6b6b00000001, %rbx
        mov     $0x6b6b6b6b00000002, %rbp
        mov     $0x6b6b6b6b00000003, %rdx
        mov     $0x6b6b6b6b00000004, %rsi
        mov     $0x6b6b6b6b00000005, %rdi
        mov     $0x6b6b6b6b00000006, %r8
        mov     $0x6b6b6b6b00000007, %r9
        mov     $0x6b6b6b6b00000008, %r10
        mov     $0x6b6b6b6b00000009, %r12
        mov     $0x6b6b6b6b0000000a, %r13
        mov     $0x6b6b6b6b0000000b, %r14
        mov     $0x6b6b6b6b0000000c, %r15
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      forked

        # The parent. fork's answer to word 2, then wait4(pid, &word 1, 0, 0).
        mov     8(%rsp), %r15           # the report page again
        mov     %rax, 16(%r15)
        mov     %rax, %rdi
        lea     8(%r15), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax               # wait4
        syscall
        mov     %rax, 24(%r15)

        # glibc's fork: clone(0x01200011, 0, 0, &word 7, 0), the word -1 first.
        movl    $-1, 56(%r15)
        mov     $0x01200011, %edi
        xor     %esi, %esi
        xor     %edx, %edx
        lea     56(%r15), %r10
        xor     %r8d, %r8d
        mov     $56, %eax               # clone
        syscall
        test    %rax, %rax
        jz      cloned
        mov     %rax, 40(%r15)
        mov     %rax, %rdi
        lea     32(%r15), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax               # wait4
        syscall
        mov     %rax, 48(%r15)
        movq    $1, (%r15)              # done; the kernel reads the page and ends this
        jmp     .

        # One general register against what the parent put there.
        .macro  expect reg, value
        mov     $\value, %rcx
        cmp     %rcx, \reg
        je      1f
        inc     %rax
1:
        .endm

forked:
        # rax is zero -- the branch says so -- and counts from here; rcx and r11
        # are the syscall's own and free.
        expect  %rbx, 0x6b6b6b6b00000001
        expect  %rbp, 0x6b6b6b6b00000002
        expect  %rdx, 0x6b6b6b6b00000003
        expect  %rsi, 0x6b6b6b6b00000004
        expect  %rdi, 0x6b6b6b6b00000005
        expect  %r8, 0x6b6b6b6b00000006
        expect  %r9, 0x6b6b6b6b00000007
        expect  %r10, 0x6b6b6b6b00000008
        expect  %r12, 0x6b6b6b6b00000009
        expect  %r13, 0x6b6b6b6b0000000a
        expect  %r14, 0x6b6b6b6b0000000b
        expect  %r15, 0x6b6b6b6b0000000c
        # The stack word at rsp, and the same word through %fs.
        mov     $0x7e57f5ba5e000001, %rcx
        cmp     %rcx, (%rsp)
        je      2f
        inc     %rax
2:
        mov     %fs:0, %r11
        cmp     %rcx, %r11
        je      3f
        inc     %rax
3:
        # Sixteen xmm registers, both halves of each: quadword q holds
        # 0x5a5a5a5a00000000 + q/2.
        sub     $256, %rsp
        movdqu  %xmm0, 0(%rsp)
        movdqu  %xmm1, 16(%rsp)
        movdqu  %xmm2, 32(%rsp)
        movdqu  %xmm3, 48(%rsp)
        movdqu  %xmm4, 64(%rsp)
        movdqu  %xmm5, 80(%rsp)
        movdqu  %xmm6, 96(%rsp)
        movdqu  %xmm7, 112(%rsp)
        movdqu  %xmm8, 128(%rsp)
        movdqu  %xmm9, 144(%rsp)
        movdqu  %xmm10, 160(%rsp)
        movdqu  %xmm11, 176(%rsp)
        movdqu  %xmm12, 192(%rsp)
        movdqu  %xmm13, 208(%rsp)
        movdqu  %xmm14, 224(%rsp)
        movdqu  %xmm15, 240(%rsp)
        xor     %ecx, %ecx
4:
        mov     %rcx, %rdx
        shr     $1, %rdx
        mov     $0x5a5a5a5a00000000, %rbx
        add     %rdx, %rbx
        cmp     %rbx, (%rsp,%rcx,8)
        je      5f
        inc     %rax
5:
        inc     %ecx
        cmp     $32, %ecx
        jne     4b
        # MXCSR.
        stmxcsr (%rsp)
        cmpl    $0xff80, (%rsp)
        je      6f
        inc     %rax
6:
        add     $256, %rsp
        mov     %rax, %rdi
        mov     $231, %eax              # exit_group(count)
        syscall
        jmp     .

cloned:
        # rcx and r11 are the syscall's; r13 collects one bit per wrong answer.
        xor     %r13d, %r13d
        cmp     $0x01200011, %rdi       # clone read rdi and left it
        je      7f
        or      $1, %r13d
7:
        lea     56(%r15), %rcx          # and r10, the tid word's address
        cmp     %rcx, %r10
        je      8f
        or      $2, %r13d
8:
        mov     $39, %eax               # getpid
        syscall
        mov     %rax, %rbx
        mov     $186, %eax              # gettid
        syscall
        cmp     %rax, %rbx              # a first thread's tid is its pid
        je      9f
        or      $4, %r13d
9:
        mov     56(%r15), %ecx          # this copy's tid word holds it
        cmp     %ecx, %ebx
        je      10f
        or      $8, %r13d
10:
        mov     %r13, %rdi
        mov     $231, %eax              # exit_group(bits)
        syscall
        jmp     .
