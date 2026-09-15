        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0079's witness: a hosted process ends a child of its own with a
        # signal, collects the status, and is refused every process outside its
        # own tree.
        #
        # **The child runs in a page this program mapped itself, and that is
        # not an accident.** A fork copies the regions the *personality*
        # recorded, which is what `mmap` answered and nothing else -- an
        # `execve`'s own segments are not among them. The parent keeps its whole
        # address space across a fork and needs nothing; the child arrives with
        # an instruction pointer and a copy of the recorded regions, so the few
        # instructions it executes must live in one of them. Hence a routine
        # copied into an anonymous page, called rather than jumped into: the
        # parent returns out of it to the code page it came from, and the child
        # never leaves it.
_start:
        mov     %rdi, %r12              # the report page

        mov     $39, %eax               # getpid
        syscall
        mov     %rax, (%r12)            # word 0
        mov     %rax, %r14
        # **A milestone word, because a report of zeros cannot say which call
        # stopped a probe.** Every step below writes the next number here, so a
        # run that ended early says where instead of leaving the reader to
        # guess from which fields are still zero.
        movq    $1, 120(%r12)

        # Two pages at addresses fixed by this program, because **a child
        # arrives with `rax`, its stack pointer and its instruction pointer and
        # nothing else**: it cannot be handed an address in a register, so the
        # ones it needs are constants it can name.
        #
        # **0x40000000 and not 0x30000000**, which is where `bin/linuxd` puts a
        # fork's trampoline. A page mapped there is one `map_at_eager` cannot
        # place the trampoline in, and the fork answers `ENOMEM` -- which is
        # what this probe read for three boots, and is a real limitation of
        # `fork` rather than a fact about this probe.
        #
        # mmap(DATA, 4096, PROT_READ|PROT_WRITE, PRIVATE|ANON|FIXED, -1, 0)
        mov     $0x40000000, %edi
        mov     $4096, %esi
        mov     $3, %edx
        mov     $0x32, %r10d
        mov     $-1, %r8
        xor     %r9d, %r9d
        mov     $9, %eax
        syscall
        mov     %rax, 96(%r12)          # word 12: what the data page answered
        movq    $2, 120(%r12)          # how far this got
        cmp     $0x40000000, %rax
        jne     done

        # A timespec the parked child sleeps on: a thousand seconds, which is
        # to say until somebody ends it.
        movq    $1000, 0x40000000
        movq    $0, 0x40000008

        # mmap(CODE, 4096, PROT_READ|PROT_WRITE, PRIVATE|ANON|FIXED, -1, 0).
        # Writable now and executable in a moment: W^X is refused at the plan,
        # so the two permissions are two calls and never one.
        mov     $0x40010000, %edi
        mov     $4096, %esi
        mov     $3, %edx
        mov     $0x32, %r10d
        mov     $-1, %r8
        xor     %r9d, %r9d
        mov     $9, %eax
        syscall
        mov     %rax, 104(%r12)         # word 13: what the code page answered
        movq    $3, 120(%r12)          # how far this got
        cmp     $0x40010000, %rax
        jne     done
        mov     %rax, %r15

        lea     inner(%rip), %rsi
        mov     %r15, %rdi
        mov     $inner_end - inner, %ecx
        rep movsb

        # mprotect(page, 4096, PROT_READ|PROT_EXEC)
        mov     %r15, %rdi
        mov     $4096, %esi
        mov     $5, %edx
        mov     $10, %eax
        syscall
        mov     %rax, 112(%r12)         # word 14: what mprotect answered
        movq    $4, 120(%r12)          # how far this got
        test    %rax, %rax
        js      done

        # ---- a child ended with SIGTERM ----
        call    *%r15
        mov     %rax, 8(%r12)           # word 1: the child's pid
        movq    $5, 120(%r12)          # how far this got
        mov     %rax, %r13
        test    %rax, %rax
        jle     done

        mov     %r13, %rdi              # kill(child, SIGTERM)
        mov     $15, %esi
        mov     $62, %eax
        syscall
        mov     %rax, 16(%r12)          # word 2
        movq    $6, 120(%r12)          # how far this got

        mov     %r13, %rdi              # wait4(child, &status, 0, 0)
        lea     32(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 24(%r12)          # word 3, and word 4 is the status
        movq    $7, 120(%r12)          # how far this got

        # ---- a child ended with SIGKILL while parked inside the adapter ----
        #
        # **Not spinning, and that is the point.** RFC 0080 bounds a thread that
        # makes no system call: it is caught at the next tick. A thread parked
        # *in* the adapter is the other case — it is asleep in a call, which is
        # the state a `^C` at a shell has to be able to end — and a gate whose
        # targets all spin would never touch it.
        lea     (park - inner)(%r15), %rax
        call    *%rax
        mov     %rax, 40(%r12)          # word 5
        movq    $8, 120(%r12)          # how far this got
        mov     %rax, %r13
        test    %rax, %rax
        jle     done

        mov     %r13, %rdi              # kill(child, SIGKILL)
        mov     $9, %esi
        mov     $62, %eax
        syscall
        mov     %rax, 48(%r12)          # word 6
        movq    $9, 120(%r12)          # how far this got

        mov     %r13, %rdi              # wait4(child, &status, 0, 0)
        lea     64(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 56(%r12)          # word 7, and word 8 is the status
        movq    $10, 120(%r12)          # how far this got

        # ---- who can this process see at all? ----
        #
        # `kill(pid, 0)` is the probe that changes nothing, and the answer must
        # be `OK` for this process alone: both children have been collected by
        # now, and everything else on this machine is outside its tree.
        xor     %ebx, %ebx
        mov     $1, %r13d
sweep:
        mov     %r13, %rdi
        xor     %esi, %esi
        mov     $62, %eax
        syscall
        test    %rax, %rax
        jnz     1f
        inc     %ebx
1:      inc     %r13d
        cmp     $40, %r13d
        jle     sweep
        mov     %rbx, 72(%r12)          # word 9
        movq    $11, 120(%r12)          # how far this got

        # ---- and can it end any of them? ----
        #
        # `SIGKILL` at every pid that is not this one, which must answer `ESRCH`
        # every time. `ESRCH` rather than `EPERM` is the point: a process may
        # not learn that a process it cannot touch is there.
        xor     %ebx, %ebx
        mov     $1, %r13d
strangers:
        cmp     %r14, %r13
        je      2f
        mov     %r13, %rdi
        mov     $9, %esi
        mov     $62, %eax
        syscall
        cmp     $-3, %rax
        je      2f
        inc     %ebx
2:      inc     %r13d
        cmp     $40, %r13d
        jle     strangers
        mov     %rbx, 80(%r12)          # word 10
        movq    $12, 120(%r12)          # how far this got

        # ---- a sibling ends a sibling, and the parent collects it ----
        #
        # **RFC 0079's third unresolved question, which nothing tested.** The
        # rule permits this: a process may signal any member of its own process
        # group, and two children of one parent are in one group. What was not
        # known is what the *parent* then sees -- a `kill` carried out by
        # somebody other than the parent still has to leave a status the parent
        # can collect, or the signal is a lie told to whoever is waiting.
        #
        # B spins; its pid goes in the data page, which a fork copies, so the
        # sibling forked next can name it without being handed a register.
        call    *%r15
        mov     %rax, 128(%r12)         # word 16: the one that will be ended
        movq    $13, 120(%r12)
        mov     %rax, %r13
        test    %rax, %rax
        jle     done
        mov     %r13, 0x40000010

        lea     (sibling - inner)(%r15), %rax
        call    *%rax
        mov     %rax, 136(%r12)         # word 17: the one that ends it
        mov     %rax, %rbx
        test    %rax, %rax
        jle     done

        # The sibling exits with what its `kill` answered, negated, so zero is
        # acceptance -- the only way it can report anything, since its copy of
        # the data page is its own and nothing it writes comes back here.
        mov     %rbx, %rdi
        lea     152(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 144(%r12)         # word 18, and word 19 is its status

        # **And the question itself**: does this return? The parent did not send
        # the signal and was not told it was coming.
        mov     %r13, %rdi
        lea     168(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 160(%r12)         # word 20, and word 21 is the status
        movq    $14, 120(%r12)

        movq    $0xC0FFEE, 88(%r12)     # word 11: every step above ran
done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .

        # The routine the child runs, copied into a page the personality
        # recorded. Ten bytes, because everything the child does after `fork`
        # has to be reachable in an address space that holds the mapped regions
        # and nothing else.
inner:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      3f
        ret                             # the parent, back to its own page
3:      jmp     .                       # the child, until somebody ends it

        # The same, except that the child goes to sleep in the adapter instead
        # of spinning. The timespec is at a fixed address because a forked child
        # is handed no registers to find one with.
park:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      4f
        ret
4:      mov     $0x40000000, %edi       # nanosleep(&{1000, 0}, NULL)
        xor     %esi, %esi
        mov     $35, %eax
        syscall
        jmp     .

        # The same fork, except that the child ends a *sibling* -- a process it
        # did not create and is not descended from, reachable only because the
        # two share a process group. Its pid is read out of the data page,
        # which is where its parent left it before this fork copied the page.
sibling:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      5f
        ret
5:      mov     0x40000010, %edi        # the sibling to end
        mov     $9, %esi                # SIGKILL
        mov     $62, %eax
        syscall
        mov     %rax, %rdi              # exit_group(-answer): 0 is acceptance
        neg     %rdi
        mov     $231, %eax
        syscall
        jmp     .
inner_end:
