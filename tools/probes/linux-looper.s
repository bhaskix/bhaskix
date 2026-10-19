        .text
        .globl _start
        # IPv4 TCP loopback, 2026-10-19: a hosted program dials its own
        # listener over 127.0.0.1. rdi = a writable page, rsi = a sockaddr_in
        # for 127.0.0.1:12 the kernel placed beside the code. One word per
        # answer in the page, and word 30, written last, says it finished:
        #
        #   0 listener socket   1 bind   2 listen   3 dialler socket
        #   4 connect (EINPROGRESS)   5 poll(OUT)   6 its revents
        #   7 getsockopt   8 SO_ERROR   9 accept4
        #   10 the first eight bytes of the peer accept4 named
        #   11 getpeername   12 the first eight bytes of the peer it named
        #   13 write dialler->accepted   14 read   15 those 16 bytes matched
        #   16 write accepted->dialler   17 read   18 those 16 bytes matched
        #   19 three closes, each answer plus one, summed
        #   20 socket, 21 bind, 22 listen, listening again on 127.0.0.1:12
        #      after the close -- RFC 0092 step 0's measurement   30 finished
        #
        # It stops at the first answer that is not the expected one.
_start:
        mov     %rdi, %r12              # the page
        mov     %rsi, %r14              # the sockaddr

        # L = socket(AF_INET, SOCK_STREAM, 0) -- blocking, so accept4 waits
        mov     $2, %edi
        mov     $1, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     %rax, 0(%r12)
        test    %rax, %rax
        js      done
        mov     %rax, %r13

        # bind(L, 127.0.0.1:12, 16), listen(L, 1)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $49, %eax
        syscall
        mov     %rax, 8(%r12)
        test    %rax, %rax
        jnz     done
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $50, %eax
        syscall
        mov     %rax, 16(%r12)
        test    %rax, %rax
        jnz     done

        # C = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     %rax, 24(%r12)
        test    %rax, %rax
        js      done
        mov     %rax, %rbx

        # connect(C, 127.0.0.1:12, 16) -- EINPROGRESS (-115)
        mov     %rbx, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 32(%r12)
        cmp     $-115, %rax
        jne     done

        # poll({C, POLLOUT}, 1, 10) until it answers, at most 500 times
        mov     %ebx, 256(%r12)
        movw    $4, 260(%r12)
        mov     $500, %r15d
writable:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        mov     %rax, 40(%r12)
        movzwq  262(%r12), %rcx
        mov     %rcx, 48(%r12)
        cmp     $1, %rax
        je      settled
        dec     %r15d
        jnz     writable
        jmp     done

        # getsockopt(C, SOL_SOCKET, SO_ERROR, &value, &length) -- 0
settled:
        movl    $0xffffffff, 288(%r12)
        movl    $4, 292(%r12)
        mov     %rbx, %rdi
        mov     $1, %esi
        mov     $4, %edx
        lea     288(%r12), %r10
        lea     292(%r12), %r8
        mov     $55, %eax
        syscall
        mov     %rax, 56(%r12)
        movl    288(%r12), %ecx
        mov     %rcx, 64(%r12)
        test    %rax, %rax
        jnz     done
        test    %ecx, %ecx
        jnz     done

        # A = accept4(L, &peer, &length, 0) -- the connection the dial made
        movl    $16, 336(%r12)
        mov     %r13, %rdi
        lea     320(%r12), %rsi
        lea     336(%r12), %rdx
        xor     %r10d, %r10d
        mov     $288, %eax
        syscall
        mov     %rax, 72(%r12)
        test    %rax, %rax
        js      done
        mov     %rax, %rbp
        mov     320(%r12), %rcx
        mov     %rcx, 80(%r12)

        # getpeername(C, &peer, &length) -- 127.0.0.1:12
        movl    $16, 368(%r12)
        mov     %rbx, %rdi
        lea     352(%r12), %rsi
        lea     368(%r12), %rdx
        mov     $52, %eax
        syscall
        mov     %rax, 88(%r12)
        mov     352(%r12), %rcx
        mov     %rcx, 96(%r12)
        test    %rax, %rax
        jnz     done

        # write(C, "bhaskix-loopback", 16), then a blocking read(A) of it
        movabs  $0x2d78696b73616862, %rax   # "bhaskix-"
        movabs  $0x6b636162706f6f6c, %rcx   # "loopback"
        mov     %rax, 384(%r12)
        mov     %rcx, 392(%r12)
        mov     %rbx, %rdi
        lea     384(%r12), %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall
        mov     %rax, 104(%r12)
        cmp     $16, %rax
        jne     done
        mov     %rbp, %rdi
        lea     400(%r12), %rsi
        mov     $16, %edx
        xor     %eax, %eax
        syscall
        mov     %rax, 112(%r12)
        cmp     $16, %rax
        jne     done
        mov     384(%r12), %rax
        cmp     400(%r12), %rax
        jne     done
        mov     392(%r12), %rax
        cmp     408(%r12), %rax
        jne     done
        movq    $1, 120(%r12)

        # write(A, the same 16), then poll C for them and read
        mov     %rbp, %rdi
        lea     400(%r12), %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall
        mov     %rax, 128(%r12)
        cmp     $16, %rax
        jne     done
        movw    $1, 260(%r12)
        mov     $500, %r15d
readable:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        cmp     $1, %rax
        je      arrived
        dec     %r15d
        jnz     readable
        jmp     done
arrived:
        mov     %rbx, %rdi
        lea     416(%r12), %rsi
        mov     $16, %edx
        xor     %eax, %eax
        syscall
        mov     %rax, 136(%r12)
        cmp     $16, %rax
        jne     done
        mov     384(%r12), %rax
        cmp     416(%r12), %rax
        jne     done
        mov     392(%r12), %rax
        cmp     424(%r12), %rax
        jne     done
        movq    $1, 144(%r12)

        # close(A), close(C), close(L) -- each answer plus one, summed
        xor     %r15d, %r15d
        mov     %rbp, %rdi
        mov     $3, %eax
        syscall
        lea     1(%r15, %rax), %r15
        mov     %rbx, %rdi
        mov     $3, %eax
        syscall
        lea     1(%r15, %rax), %r15
        mov     %r13, %rdi
        mov     $3, %eax
        syscall
        lea     1(%r15, %rax), %r15
        mov     %r15, 152(%r12)

        # RFC 0092 step 0: listen again on the port just closed. A listener
        # that cannot be closed answers this with an error; read, not judged.
        mov     $2, %edi
        mov     $1, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     %rax, 160(%r12)
        test    %rax, %rax
        js      done
        mov     %rax, %r13
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $49, %eax
        syscall
        mov     %rax, 168(%r12)
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $50, %eax
        syscall
        mov     %rax, 176(%r12)
        mov     %r13, %rdi
        mov     $3, %eax
        syscall

done:
        movq    $1, 240(%r12)
        # Stay, and let the kernel end this domain once it has read the page
        # -- linux-dialer.s says why.
idle:
        pause
        jmp     idle
