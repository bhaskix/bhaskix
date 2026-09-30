        .text
        .globl _start
        # RFC 0086 step 4: a hosted Linux program serving one TCP client
        # through `epoll`, the way Go's netpoller does.
        #
        # rdi = a writable page, rsi = a sockaddr_in for 0.0.0.0:11 the kernel
        # placed beside the code.
        #
        # **Non-blocking descriptors and edge-triggered interest, on purpose.**
        # The listener and the connection are both `SOCK_NONBLOCK`, so nothing
        # here waits except `epoll_wait`: a probe that also blocked in `accept4`
        # or `read` would pass on an `epoll` that never reported anything. The
        # connection is watched `EPOLLIN | EPOLLRDHUP | EPOLLET`, and read until
        # `EAGAIN` before waiting again -- the host sends its sixteen bytes in
        # two halves with a pause between, so the second half arrives only as a
        # second edge.
        #
        # `epoll_wait` for ever may come back with zero events here: the
        # adapter answers so before the nucleus's sixteen-park limit. Linux's
        # callers loop on that and so does this.
_start:
        mov     %rdi, %r12              # the page
        mov     %rsi, %r14              # the sockaddr

        # socket(AF_INET = 2, SOCK_STREAM | SOCK_NONBLOCK = 0x801, 0)
        mov     $2, %edi
        mov     $0x801, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        mov     $1, %ebp
        test    %rax, %rax
        js      fail
        mov     %rax, %r13              # the listener

        # bind(fd, sockaddr, 16)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $49, %eax
        syscall
        mov     $2, %ebp
        test    %rax, %rax
        js      fail

        # listen(fd, 1)
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $50, %eax
        syscall
        mov     $3, %ebp
        test    %rax, %rax
        js      fail

        # epoll_create1(EPOLL_CLOEXEC = 0x80000)
        mov     $0x80000, %edi
        mov     $291, %eax
        syscall
        mov     $4, %ebp
        test    %rax, %rax
        js      fail
        mov     %rax, %r15              # the set

        # epoll_ctl(set, EPOLL_CTL_ADD, listener, {EPOLLIN, 'l'}) -- the event
        # is twelve packed bytes at 64(page)
        movl    $1, 64(%r12)
        movq    $0x6c, 68(%r12)
        mov     %r15, %rdi
        mov     $1, %esi
        mov     %r13, %rdx
        lea     64(%r12), %r10
        mov     $233, %eax
        syscall
        mov     $5, %ebp
        test    %rax, %rax
        js      fail

        # epoll_wait(set, 128(page), 4, -1) until the listener is readable
listener:
        mov     %r15, %rdi
        lea     128(%r12), %rsi
        mov     $4, %edx
        mov     $0xffffffff, %r10d      # an `int` -1, as a compiler passes it
        mov     $232, %eax
        syscall
        mov     $6, %ebp
        test    %rax, %rax
        js      fail
        jz      listener
        cmpq    $0x6c, 132(%r12)        # the data word handed back is ours
        mov     $-0xee, %rax
        jne     fail

        # accept4(listener, NULL, NULL, SOCK_NONBLOCK)
        mov     %r13, %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        mov     $0x800, %r10d
        mov     $288, %eax
        syscall
        mov     $7, %ebp
        test    %rax, %rax
        js      fail
        mov     %rax, %rbx              # the connection

        # epoll_ctl(set, ADD, conn, {EPOLLIN | EPOLLRDHUP | EPOLLET, 'c'})
        movl    $0x80002001, 64(%r12)
        movq    $0x63, 68(%r12)
        mov     %r15, %rdi
        mov     $1, %esi
        mov     %rbx, %rdx
        lea     64(%r12), %r10
        mov     $233, %eax
        syscall
        mov     $8, %ebp
        test    %rax, %rax
        js      fail

        xor     %r14d, %r14d            # bytes read so far
connection:
        mov     %r15, %rdi
        lea     128(%r12), %rsi
        mov     $4, %edx
        mov     $0xffffffff, %r10d
        mov     $232, %eax
        syscall
        mov     $8, %ebp
        test    %rax, %rax
        js      fail
        jz      connection

        # read until EAGAIN, which spends the edge, or until sixteen bytes
drain:
        mov     %rbx, %rdi
        lea     (%r12,%r14), %rsi
        mov     $16, %edx
        sub     %r14d, %edx
        xor     %eax, %eax              # read
        syscall
        cmp     $-11, %rax              # EAGAIN: wait for the next edge
        je      connection
        mov     $9, %ebp
        test    %rax, %rax
        jle     fail
        add     %rax, %r14
        cmp     $16, %r14
        jl      drain

        # write(conn, page, 16) -- the host's bytes, back to the host
        mov     %rbx, %rdi
        mov     %r12, %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall

        # write(1, page, 16) -- and to the console
        mov     $1, %edi
        mov     %r12, %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall

        # close(conn)
        mov     %rbx, %rdi
        mov     $3, %eax
        syscall

done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .

        # **Why it stopped, said on the console**, as the stream probe does:
        # `ebp` is the step (1 socket, 2 bind, 3 listen, 4 epoll_create1,
        # 5 adding the listener, 6 waiting on it -- `ee` is the wrong data word
        # handed back -- 7 accept4, 8 adding or waiting on the connection,
        # 9 read), `rax` what the call answered; the low byte of its negation
        # is printed in hex.
fail:
        neg     %rax
        lea     hex(%rip), %rsi
        mov     %eax, %ecx
        and     $0xf, %ecx
        movb    (%rsi,%rcx), %dl
        movb    %dl, 13(%r12)
        mov     %eax, %ecx
        shr     $4, %ecx
        and     $0xf, %ecx
        movb    (%rsi,%rcx), %dl
        movb    %dl, 12(%r12)
        movl    $0x6c6f7065, (%r12)     # "epol"
        movl    $0x69616620, 4(%r12)    # " fai"
        movw    $0x206c, 8(%r12)        # "l "
        lea     0x30(%rbp), %eax
        movb    %al, 10(%r12)           # the step, as a digit
        movb    $0x20, 11(%r12)         # " "
        movb    $0x0a, 14(%r12)         # newline
        mov     $1, %edi
        mov     %r12, %rsi
        mov     $15, %edx
        mov     $1, %eax
        syscall
        jmp     done
hex:
        .ascii  "0123456789abcdef"
