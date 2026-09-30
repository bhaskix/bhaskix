        .text
        .globl _start
        # RFC 0086 step 3b: a hosted Linux program serving one TCP client.
        #
        # rdi = a writable page, rsi = a sockaddr_in for 0.0.0.0:10 the kernel
        # placed beside the code -- handed over rather than computed, as every
        # probe here takes its address.
        #
        # **Blocking calls, on purpose.** `accept4` and `read` are the ones a
        # plain server makes, and whether a blocking call on a hosted stream
        # waits and comes back is the thing under test: the adapter parks the
        # caller and retries. A probe written with non-blocking retries would
        # pass on an adapter that never waited at all.
_start:
        mov     %rdi, %r12              # the buffer
        mov     %rsi, %r14              # the sockaddr

        # socket(AF_INET = 2, SOCK_STREAM = 1, 0)
        mov     $2, %edi
        mov     $1, %esi
        xor     %edx, %edx
        mov     $41, %eax
        syscall
        test    %rax, %rax
        mov     $1, %ebp
        js      fail
        mov     %rax, %r13              # the listening descriptor

        # bind(fd, sockaddr, 16)
        mov     %r13, %rdi
        mov     %r14, %rsi
        mov     $16, %edx
        mov     $49, %eax
        syscall
        test    %rax, %rax
        mov     $2, %ebp
        js      fail

        # listen(fd, 1)
        mov     %r13, %rdi
        mov     $1, %esi
        mov     $50, %eax
        syscall
        test    %rax, %rax
        mov     $3, %ebp
        js      fail

        # accept4(fd, NULL, NULL, 0) -- waits for the host
        mov     %r13, %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $288, %eax
        syscall
        test    %rax, %rax
        mov     $4, %ebp
        js      fail
        mov     %rax, %rbx              # the connection

        # read until sixteen bytes have come, each read waiting for more
        xor     %r15d, %r15d
more:
        mov     %rbx, %rdi
        lea     (%r12,%r15), %rsi
        mov     $16, %edx
        sub     %r15d, %edx
        xor     %eax, %eax              # read
        syscall
        mov     $5, %ebp
        test    %rax, %rax
        jle     fail
        add     %rax, %r15
        cmp     $16, %r15
        jl      more

        # write(conn, buf, 16) -- the host's bytes, back to the host
        mov     %rbx, %rdi
        mov     %r12, %rsi
        mov     $16, %edx
        mov     $1, %eax
        syscall

        # write(1, buf, 16) -- and to the console, which no part of the adapter
        # could have invented
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

        # **Why it stopped, said on the console** -- because "the probe ended"
        # is true whether it served the host or failed its first call, and a
        # suite run once failed here with nothing to say which. `ebp` is the
        # step (1 socket, 2 bind, 3 listen, 4 accept4, 5 read), `rax` what the
        # call answered; the low byte of its negation is printed in hex.
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
        movl    $0x70637468, (%r12)     # "htcp"
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
