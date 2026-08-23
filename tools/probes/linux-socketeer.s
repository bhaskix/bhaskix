        .text
        .globl _start
        # rdi = a writable page, rsi = a sockaddr_in6 for [::1]:7777 the
        # kernel placed beside the code. Handed over rather than computed,
        # which is the affordance every probe here uses.
_start:
        mov     %rdi, %r12              # the buffer
        mov     %rsi, %r14              # the sockaddr

        # socket(AF_INET6 = 10, SOCK_DGRAM = 2, 0)
        mov     $10, %edi
        mov     $2, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13              # the descriptor

        # bind(fd, sockaddr, 28)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $28, %edx
        mov     $49, %eax
        syscall
        test    %rax, %rax
        js      done

        # The payload: four bytes nothing else on this machine writes.
        movl    $0x30707564, (%r12)     # "dup0"

        # sendto(fd, buf, 4, 0, sockaddr, 28) -- to itself, over [::1]
        mov     %r13, %rdi
        mov     %r12, %rsi
        mov     $4, %edx
        xor     %r10d, %r10d
        mov     %r14, %r8
        mov     $28, %r9d
        mov     $44, %eax
        syscall
        test    %rax, %rax
        js      done

        # recvfrom in a bounded retry: the adapter answers EAGAIN until the
        # datagram has been round the protocol service and come back, and a
        # loop without a bound is a hang rather than a test.
        # **Twelve, and the bound is measured rather than guessed.** Every
        # retry is a foreign call the single-threaded adapter serves and an
        # IPC round trip to bin/ipd: about 1.5 million cycles each under TCG,
        # which is tens of milliseconds. Two thousand did not finish inside
        # the boot test's 120 seconds. Sixty-four fitted on the iommu lane and
        # did *not* fit inside the self-test's wait on uefi and shell -- a
        # bound that passes on the fastest lane and fails on the others is a
        # bound chosen by looking at one machine.
        #
        # A datagram that has been round the loopback path is there on the
        # first or second try. Twelve is generous for that and cheap enough to
        # exhaust on a lane where it never arrives, which is the case the wait
        # has to cover.
        mov     $12, %r15d
retry:
        lea     64(%r12), %rsi
        mov     %r13, %rdi
        mov     $4, %edx
        xor     %r10d, %r10d
        xor     %r8d, %r8d
        xor     %r9d, %r9d
        mov     $45, %eax
        syscall
        test    %rax, %rax
        jg      arrived
        dec     %r15d
        jnz     retry
        jmp     done

        # write(1, buffer + 64, that many) -- the bytes that went out and came
        # back, which no part of the adapter could have invented.
arrived:
        mov     %rax, %rdx
        lea     64(%r12), %rsi
        mov     $1, %edi
        mov     $1, %eax
        syscall

done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .
