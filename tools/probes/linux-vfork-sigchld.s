        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0099: **children a shell and Go can start and hear from.**
        #
        # 1. A vfork with Go's flags (`CLONE_VFORK | CLONE_VM | SIGCHLD`, no
        #    stack, the shape Go 1.27.1's os/exec makes). Its child yields a while
        #    and exits with 7. The parent is held until then, so the moment its
        #    `clone` returns, `wait4(pid, WNOHANG)` must collect the child -- a
        #    parent that was not held finds it still running and is answered 0.
        # 2. The child's SIGCHLD must have reached the parent's handler, once.
        # 3. With SIGCHLD set to SIG_IGN, a forked child reaps itself: `wait4(-1)`
        #    must answer ECHILD rather than collect it.
        # 4. With SIGTERM set to SIG_IGN, `kill(self, SIGTERM)` is ignored: the
        #    process carries on. Until RFC 0099 SIG_IGN read as a handler at
        #    address 1.
        #
        # The page: word 0 one once done; word 1 the vfork's pid; word 2 what
        # the WNOHANG `wait4` answered; word 3 its status; word 4 the handler's
        # count after it; word 5 what `wait4(-1)` answered under SIG_IGN; word 6
        # what `kill` answered; word 7 one if the process survived it; word 8
        # the handler's count at the end; word 9 the count the handler keeps.
        #
        # The handler finds the page from its own address: `enter_probe` puts
        # the report page 0x20000 above the code, and the code starts at
        # `origin`. A local label, because a reference to the global `_start`
        # assembles as a relocation, and `probe-bytes.sh` copies bytes without
        # applying one: the displacement would have been zero.
_start:
origin:
        mov     %rdi, %r15              # the report page

        # rt_sigaction(SIGCHLD, {handler, SA_SIGINFO|SA_RESTORER, restorer, 0})
        push    $0                      # sa_mask
        lea     restorer(%rip), %rax
        push    %rax                    # sa_restorer
        mov     $0x04000004, %eax       # SA_SIGINFO | SA_RESTORER
        push    %rax                    # sa_flags
        lea     handler(%rip), %rax
        push    %rax                    # sa_handler
        mov     %rsp, %rsi
        mov     $17, %edi               # SIGCHLD
        xor     %edx, %edx
        mov     $8, %r10d
        mov     $13, %eax               # rt_sigaction
        syscall
        add     $32, %rsp

        # 1. clone(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, 0, 0)
        mov     $0x4111, %edi
        xor     %esi, %esi
        xor     %edx, %edx
        xor     %r10d, %r10d
        xor     %r8d, %r8d
        mov     $56, %eax               # clone
        syscall
        test    %rax, %rax
        jz      vchild
        mov     %rax, 8(%r15)           # the vfork's pid
        mov     %rax, %rdi
        lea     24(%r15), %rsi          # status
        mov     $1, %edx                # WNOHANG
        xor     %r10d, %r10d
        mov     $61, %eax               # wait4
        syscall
        mov     %rax, 16(%r15)
        mov     $39, %eax               # getpid: one more call, for delivery
        syscall
        mov     72(%r15), %rcx
        mov     %rcx, 32(%r15)          # 2. the handler's count

        # 3. rt_sigaction(SIGCHLD, {SIG_IGN}), a fork, wait4(-1)
        push    $0
        push    $0
        push    $0
        push    $1                      # SIG_IGN
        mov     %rsp, %rsi
        mov     $17, %edi
        xor     %edx, %edx
        mov     $8, %r10d
        mov     $13, %eax
        syscall
        add     $32, %rsp
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      fchild
        mov     $-1, %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax               # wait4(-1, 0, 0, 0)
        syscall
        mov     %rax, 40(%r15)          # ECHILD expected

        # 4. rt_sigaction(SIGTERM, {SIG_IGN}), kill(self, SIGTERM)
        push    $0
        push    $0
        push    $0
        push    $1                      # SIG_IGN
        mov     %rsp, %rsi
        mov     $15, %edi               # SIGTERM
        xor     %edx, %edx
        mov     $8, %r10d
        mov     $13, %eax
        syscall
        add     $32, %rsp
        mov     $39, %eax               # getpid
        syscall
        mov     %rax, %rdi
        mov     $15, %esi
        mov     $62, %eax               # kill
        syscall
        mov     %rax, 48(%r15)
        movq    $1, 56(%r15)            # it survived
        mov     72(%r15), %rcx
        mov     %rcx, 64(%r15)          # the handler's count at the end
        movq    $1, (%r15)              # done; the kernel reads the page and ends this
        jmp     .

vchild:
        mov     $100, %ebx
1:
        mov     $24, %eax               # sched_yield
        syscall
        dec     %ebx
        jnz     1b
        mov     $7, %edi
        mov     $231, %eax              # exit_group(7)
        syscall
        jmp     .

fchild:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group(0)
        syscall
        jmp     .

handler:
        lea     origin+0x20000(%rip), %rax
        incq    72(%rax)                # word 9
        ret                             # into the restorer

restorer:
        mov     $15, %eax               # rt_sigreturn
        syscall
        jmp     restorer
