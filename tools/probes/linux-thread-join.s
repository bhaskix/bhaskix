        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0097: **a thread glibc can join.** glibc's `pthread_create` clones
        # with `0x3d0f00` -- the thread shares, `SETTLS`, `CLONE_PARENT_SETTID`
        # and `CLONE_CHILD_CLEARTID` -- naming one word, the thread's tid word,
        # for both; and `pthread_join` waits on that word with a *shared*
        # `FUTEX_WAIT` until the thread's `exit` clears it (traced on the build
        # host, glibc 2.31, 2026-10-31). This probe makes the same three calls:
        # the word must hold the new thread's tid as soon as `clone` returns,
        # and the creator's wait must end because the word was cleared and the
        # creator woken -- not because it gave up.
        #
        # The page: word 0 one once done; word 1 the tid `clone` answered; word
        # 2 the tid word as it read straight after `clone`; word 3 how many
        # waits the join made; word 4 the last wait's answer; word 5 the word
        # after the join (0); word 8 is the tid word itself.
        #
        # The join is bounded at 100,000 waits, so a wait refused with `ENOSYS`
        # -- which glibc 2.31 retries -- ends the probe with an answer rather
        # than spinning it for ever.
_start:
        mov     %rdi, %r15              # the report page
        movl    $0, 64(%r15)            # the tid word

        # clone(0x3d0f00, stack, &word, &word, tls)
        mov     $0x3d0f00, %edi
        lea     -0x2000(%rsp), %rsi     # the thread's stack, below this one
        and     $-16, %rsi
        lea     64(%r15), %rdx          # CLONE_PARENT_SETTID
        lea     64(%r15), %r10          # CLONE_CHILD_CLEARTID
        lea     0x800(%r15), %r8        # a TLS base nothing reads
        mov     $56, %eax               # clone
        syscall
        test    %rax, %rax
        jz      thread
        mov     %rax, 8(%r15)           # the tid clone answered
        mov     64(%r15), %ecx
        mov     %rcx, 16(%r15)          # the word, at once

        # pthread_join: while the word is not zero, a shared FUTEX_WAIT on it.
        xor     %r12d, %r12d            # waits made
join:
        mov     64(%r15), %edx          # expected: what the word holds now
        test    %edx, %edx
        jz      joined
        lea     64(%r15), %rdi
        xor     %esi, %esi              # FUTEX_WAIT, not private
        xor     %r10d, %r10d            # no timeout
        mov     $202, %eax              # futex
        syscall
        mov     %rax, 32(%r15)          # its answer
        inc     %r12
        cmp     $100000, %r12
        jb      join
joined:
        mov     %r12, 24(%r15)
        mov     64(%r15), %ecx
        mov     %rcx, 40(%r15)          # the word after the join
        movq    $1, (%r15)              # done; the kernel reads the page and ends this
        jmp     .

thread:
        # Yield a while, so that the creator is usually parked in its wait by
        # the time this exits, and the wake is what ends it.
        mov     $200, %ebx
1:
        mov     $24, %eax               # sched_yield
        syscall
        dec     %ebx
        jnz     1b
        xor     %edi, %edi
        mov     $60, %eax               # exit: this thread only
        syscall
        jmp     .
