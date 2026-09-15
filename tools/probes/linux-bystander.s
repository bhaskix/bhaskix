        .text
        .globl _start
        # rdi = a writable page the kernel reads and writes.
        #
        # **A hosted process in nobody's tree, holding a child that can really
        # be taken from it.** RFC 0079's containment gate has to be armable:
        # removing the tree check must not only turn it red, it must leave a
        # target dead, or what the gate proves is that a refusal was printed
        # rather than that anything was prevented.
        #
        # A child forked *here* is one the adapter keeps a domain capability
        # for, so a `kill` from outside this tree could genuinely end it — and
        # this process is in neither the killer probe's descent nor its process
        # group, so the rule must refuse. After the kernel says the killer has
        # finished, this asks `wait4(child, WNOHANG)`: nothing to collect means
        # the child is still running and the refusal held; its pid and a status
        # of 9 mean it was taken.
_start:
        mov     %rdi, %r12

        mov     $39, %eax               # getpid
        syscall
        mov     %rax, 8(%r12)           # word 1: this process

        # mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        xor     %edi, %edi
        mov     $4096, %esi
        mov     $3, %edx
        mov     $0x22, %r10d
        mov     $-1, %r8
        xor     %r9d, %r9d
        mov     $9, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r15

        lea     inner(%rip), %rsi
        mov     %r15, %rdi
        mov     $inner_end - inner, %ecx
        rep movsb

        mov     %r15, %rdi              # mprotect(page, 4096, READ|EXEC)
        mov     $4096, %esi
        mov     $5, %edx
        mov     $10, %eax
        syscall
        test    %rax, %rax
        js      done

        call    *%r15                   # fork a child that spins
        mov     %rax, 24(%r12)          # word 3: the child nobody else may end
        mov     %rax, %r13
        test    %rax, %rax
        jle     done

        movq    $1, (%r12)              # word 0: standing, with a child

        # Wait for the kernel to say the killer has finished, yielding rather
        # than spinning so this does not eat a CPU the killer needs.
1:      mov     $24, %eax               # sched_yield
        syscall
        mov     16(%r12), %rax
        test    %rax, %rax
        jz      1b

        # **Word 0 says where this got to**, because a report word that is zero
        # cannot say whether it was written. `wait4` answering zero and `wait4`
        # never being reached both leave word 4 at zero, and the first time this
        # gate was armed the two were indistinguishable.
        movq    $3, (%r12)

        # wait4(child, &status, WNOHANG, 0) -- zero means it is still running.
        mov     %r13, %rdi
        lea     40(%r12), %rsi
        mov     $1, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 32(%r12)          # word 4, and word 5 is the status

        mov     %r13, %rdi              # and now end it, as its own parent may
        mov     $9, %esi
        mov     $62, %eax
        syscall
        mov     %r13, %rdi
        lea     48(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall

        movq    $2, (%r12)              # word 0: still here at the end
done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .

        # The routine the child runs, for the reason the killer probe's is:
        # a fork copies the regions the personality recorded, and this page is
        # the only one among them.
inner:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      2f
        ret                             # the parent, back to its own page
2:      jmp     .                       # the child, until its parent ends it
inner_end:
