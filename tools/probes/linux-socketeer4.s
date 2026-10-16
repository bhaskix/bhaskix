        .text
        .globl _start
        # The v4 twin of linux-socketeer.s -- RFC 0005's carried "IPv4 UDP
        # loopback, shown". rdi = a writable page, rsi = a sockaddr_in for
        # 127.0.0.1:7779 the kernel placed beside the code.
        #
        # **It asks recvfrom who sent it**, which the v6 probe does not: the
        # payload is written only if the datagram came back from exactly
        # 127.0.0.1:7779, so the bytes on the console say the source was right
        # as well as the bytes.
_start:
        mov     %rdi, %r12              # the buffer
        mov     %rsi, %r14              # the sockaddr

        # socket(AF_INET = 2, SOCK_DGRAM = 2, 0)
        mov     $2, %edi
        mov     $2, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13              # the descriptor

        # bind(fd, sockaddr, 16)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $49, %eax
        syscall
        test    %rax, %rax
        js      done

        # The payload: four bytes nothing else on this machine writes.
        movl    $0x21346f6c, (%r12)     # "lo4!"

        # sendto(fd, buf, 4, 0, sockaddr, 16) -- to itself, over 127.0.0.1
        mov     %r13, %rdi
        mov     %r12, %rsi
        mov     $4, %edx
        xor     %r10d, %r10d
        mov     %r14, %r8
        mov     $16, %r9d
        mov     $44, %eax
        syscall
        test    %rax, %rax
        js      done

        # recvfrom(fd, buf + 64, 4, 0, buf + 128, buf + 160) in the same
        # bounded retry as the v6 probe, and for its reasons.
        mov     $12, %r15d
retry:
        movl    $16, 160(%r12)          # the source's room, each time
        lea     64(%r12), %rsi
        mov     %r13, %rdi
        mov     $4, %edx
        xor     %r10d, %r10d
        lea     128(%r12), %r8
        lea     160(%r12), %r9
        mov     $45, %eax
        syscall
        test    %rax, %rax
        jg      arrived
        dec     %r15d
        jnz     retry
        jmp     done

        # The source must be AF_INET, port 7779 and 127.0.0.1 -- the first
        # eight bytes of the sockaddr_in recvfrom wrote, read as one word:
        # family 2 little-endian, the port 0x1e63 and the address 7f 00 00 01
        # big-endian.
arrived:
        mov     %rax, %rbx              # the length that came back
        movabs  $0x0100007f631e0002, %rcx
        cmp     128(%r12), %rcx
        jne     done

        # write(1, buffer + 64, that many) -- the bytes that went out and came
        # back, from where they were sent.
        mov     %rbx, %rdx
        lea     64(%r12), %rsi
        mov     $1, %edi
        mov     $1, %eax
        syscall

done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .
