        .text
        .globl _start
        # RFC 0090 step 4's probe: a hosted program dials out.
        #
        # rdi = a writable page, rsi = a sockaddr_in for 10.0.2.100:9 -- the
        # echo peer QEMU's guestfwd spawns a `cat` for -- that the kernel placed
        # beside the code. Every answer is stored in the page, one word each,
        # and the last word written says the program finished:
        #
        #   0 socket   1 connect   2 poll(OUT)   3 its revents
        #   4 getsockopt   5 SO_ERROR's value   6 write   7 poll(IN)
        #   8 its revents   9 read   10 bytes matched   11 close + 1
        #   12 round trips completed   15 finished
        #   16 refused non-blocking connect   17 its poll revents
        #   18 its SO_ERROR   19 refused blocking connect
        #   20 blocking connect that opens   21 its bytes matched
        #   22 a forked child's wait status: it dialled and exited with
        #      -connect, so 115 (EINPROGRESS) << 8 when the grant followed
        #      the fork (RFC 0090 step 7), 13 (EACCES) << 8 when there was
        #      none to follow
        #   23 fork's answer in the parent   24 wait4's answer
        #   25 a dial to 127.0.0.1: -101 (ENETUNREACH) granted, -13 not
        #
        # It stops at the first answer that is not the expected one, so a run
        # the kernel did not grant the network ends at word 1 with EACCES.
        #
        # **Sixty-four times** (RFC 0090 step 5): more dials than the adapter's
        # pool holds pairs, so the run finishes only if each dial's pair comes
        # back after its close. Words 0-11 are the last round's.
_start:
        mov     %rdi, %r12              # the page
        mov     %rsi, %r14              # the sockaddr
        xor     %ebx, %ebx              # rounds completed

round:

        # socket(AF_INET = 2, SOCK_STREAM | SOCK_NONBLOCK = 0x801, 0)
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     %rax, 0(%r12)
        test    %rax, %rax
        js      done
        mov     %rax, %r13              # the descriptor

        # connect(fd, sockaddr, 16) -- non-blocking, so EINPROGRESS (-115)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 8(%r12)
        # Not granted: the fork, then stop.
        cmp     $-13, %rax
        je      inherit
        cmp     $-115, %rax
        jne     done

        # poll({fd, POLLOUT}, 1, 10) until it answers, at most 500 times. A
        # short wait in a loop rather than one long one: a positive timeout
        # here waits it out before looking again.
        mov     %r13d, 256(%r12)
        movw    $4, 260(%r12)
        mov     $500, %r15d
writable:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        mov     %rax, 16(%r12)
        movzwq  262(%r12), %rcx
        mov     %rcx, 24(%r12)
        cmp     $1, %rax
        je      settled
        dec     %r15d
        jnz     writable
        jmp     done

        # getsockopt(fd, SOL_SOCKET = 1, SO_ERROR = 4, &value, &length)
settled:
        movl    $0xffffffff, 288(%r12)
        movl    $4, 292(%r12)
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $4, %edx
        lea     288(%r12), %r10
        lea     292(%r12), %r8
        mov     $55, %eax
        syscall
        mov     %rax, 32(%r12)
        movl    288(%r12), %ecx
        mov     %rcx, 40(%r12)
        test    %rax, %rax
        jnz     done
        test    %ecx, %ecx
        jnz     done

        # write(fd, "bhaskix-ldial-ok", 16) -- the two words little-endian
        movabs  $0x2d78696b73616862, %rax   # "bhaskix-"
        movabs  $0x6b6f2d6c6169646c, %rcx   # "ldial-ok"
        mov     %rax, 320(%r12)
        mov     %rcx, 328(%r12)
        mov     %r13, %rdi
        lea     320(%r12), %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall
        mov     %rax, 48(%r12)
        cmp     $16, %rax
        jne     done

        # poll({fd, POLLIN}, 1, 10) until it answers, at most 500 times.
        movw    $1, 260(%r12)
        mov     $500, %r15d
readable:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        mov     %rax, 56(%r12)
        movzwq  262(%r12), %rcx
        mov     %rcx, 64(%r12)
        cmp     $1, %rax
        je      arrived
        dec     %r15d
        jnz     readable
        jmp     done

        # read(fd, page + 384, 16), and the bytes compared with what went out
arrived:
        mov     %r13, %rdi
        lea     384(%r12), %rsi
        mov     $16, %edx
        xor     %eax, %eax
        syscall
        mov     %rax, 72(%r12)
        cmp     $16, %rax
        jne     done
        mov     320(%r12), %rax
        cmp     384(%r12), %rax
        jne     done
        mov     328(%r12), %rax
        cmp     392(%r12), %rax
        jne     done
        movq    $1, 80(%r12)

        # close(fd), stored plus one so that success is not zero
        mov     %r13, %rdi
        mov     $3, %eax
        syscall
        inc     %rax
        mov     %rax, 88(%r12)

        # One more round trip; again until sixty-four.
        inc     %ebx
        mov     %rbx, 96(%r12)
        cmp     $64, %ebx
        jb      round

        # RFC 0090 step 6: a dial nobody answers, both ways, then a blocking
        # dial that opens. 10.0.2.100:10 is a port no guestfwd names, so slirp
        # refuses it on every boot; its sockaddr is the one beside the code
        # with the port changed, at page + 448.
        mov     0(%r14), %rax
        mov     %rax, 448(%r12)
        mov     8(%r14), %rax
        mov     %rax, 456(%r12)
        movw    $0x0a00, 450(%r12)      # port 10, big-endian

        # Refused, non-blocking: EINPROGRESS, then poll, then SO_ERROR.
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13
        mov     %r13, %rdi
        lea     448(%r12), %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 128(%r12)
        cmp     $-115, %rax
        jne     done
        mov     %r13d, 256(%r12)
        movw    $4, 260(%r12)
        mov     $500, %r15d
refused_poll:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        cmp     $1, %rax
        je      refused_said
        dec     %r15d
        jnz     refused_poll
        jmp     done
refused_said:
        movzwq  262(%r12), %rcx
        mov     %rcx, 136(%r12)
        movl    $0, 288(%r12)
        movl    $4, 292(%r12)
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $4, %edx
        lea     288(%r12), %r10
        lea     292(%r12), %r8
        mov     $55, %eax
        syscall
        movl    288(%r12), %ecx
        mov     %rcx, 144(%r12)
        mov     %r13, %rdi
        mov     $3, %eax
        syscall

        # Refused, blocking: connect itself answers ECONNREFUSED (-111).
        mov     $2, %edi
        mov     $1, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13
        mov     %r13, %rdi
        lea     448(%r12), %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 152(%r12)
        mov     %r13, %rdi
        mov     $3, %eax
        syscall
        cmpq    $-111, 152(%r12)
        jne     done

        # A blocking dial that opens: connect answers 0, then one echo.
        mov     $2, %edi
        mov     $1, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 160(%r12)
        test    %rax, %rax
        jnz     done
        movq    $0, 384(%r12)
        movq    $0, 392(%r12)
        mov     %r13, %rdi
        lea     320(%r12), %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall
        cmp     $16, %rax
        jne     done
        mov     %r13d, 256(%r12)
        movw    $1, 260(%r12)
        mov     $500, %r15d
blocking_readable:
        movw    $0, 262(%r12)
        lea     256(%r12), %rdi
        mov     $1, %esi
        mov     $10, %edx
        mov     $7, %eax
        syscall
        cmp     $1, %rax
        je      blocking_arrived
        dec     %r15d
        jnz     blocking_readable
        jmp     done
blocking_arrived:
        mov     %r13, %rdi
        lea     384(%r12), %rsi
        mov     $16, %edx
        xor     %eax, %eax
        syscall
        cmp     $16, %rax
        jne     done
        mov     320(%r12), %rax
        cmp     384(%r12), %rax
        jne     done
        mov     328(%r12), %rax
        cmp     392(%r12), %rax
        jne     done
        movq    $1, 168(%r12)
        mov     %r13, %rdi
        mov     $3, %eax
        syscall

        # Does a forked child dial as its parent does (RFC 0090 step 7)? The
        # child dials and exits with -connect; the parent waits and keeps the
        # status. Only rax, rip and rsp survive a fork here, so the child names
        # the sockaddr by its fixed address beside the code (the kernel
        # asserts it).
inherit:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        js      done
        jnz     inherit_parent
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     %rax, %rdi
        mov     $0x1c000800, %esi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        neg     %rax
        mov     %eax, %edi
        mov     $231, %eax              # exit_group(-connect)
        syscall
        jmp     .
inherit_parent:
        mov     %rax, 184(%r12)
        mov     %rax, %rdi              # wait4(child, &status, 0, 0)
        movl    $0, 464(%r12)
        lea     464(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 192(%r12)
        movl    464(%r12), %ecx
        mov     %rcx, 176(%r12)

        # A dial to 127.0.0.1, 2026-10-16: the loopback RFC 1122 keeps inside a
        # host, which v4 TCP has no road to here, is answered ENETUNREACH
        # before anything is dialled -- and EACCES first when not granted.
        # The echo peer's sockaddr with its address changed, at page + 480.
        mov     0(%r14), %rax
        mov     %rax, 480(%r12)
        mov     8(%r14), %rax
        mov     %rax, 488(%r12)
        movl    $0x0100007f, 484(%r12)  # 127.0.0.1, network order
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13
        mov     %r13, %rdi
        lea     480(%r12), %rsi
        mov     $16, %edx
        mov     $42, %eax
        syscall
        mov     %rax, 200(%r12)
        mov     %r13, %rdi
        mov     $3, %eax
        syscall

done:
        movq    $1, 120(%r12)
        # **Stay, and let the kernel end this domain once it has read the
        # page.** Exiting here let the domain end and its page be given to
        # somebody else before the kernel read it -- an armed run read 1s
        # where the answers had been (RFC 0090 step 5). And the kernel reads
        # word 15 before the rest (2026-10-15): read last, a probe finishing
        # mid-read looked finished with nothing written.
idle:
        pause
        jmp     idle
