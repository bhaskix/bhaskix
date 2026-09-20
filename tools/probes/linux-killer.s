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

        # ---- and a fork from a process sitting on the trampoline's address ----
        #
        # **The one page a fork used to need for itself.** `bin/linuxd` wrote a
        # forked child's trampoline at a constant and the comment beside it
        # argued the address was out of the ranges `mmap` hands out -- true of a
        # hint and false of `MAP_FIXED`, where the caller names the address. A
        # hosted process that mapped this page could not fork at all, and the
        # `ENOMEM` it got back named nothing it could act on. This probe read
        # exactly that for three boots, from picking the same address by
        # accident.
        mov     $0x30000000, %edi
        mov     $4096, %esi
        mov     $3, %edx
        mov     $0x32, %r10d
        mov     $-1, %r8
        xor     %r9d, %r9d
        mov     $9, %eax
        syscall
        mov     %rax, 176(%r12)         # word 22: the trampoline's own address
        cmp     $0x30000000, %rax
        jne     done

        call    *%r15                   # and now fork, standing on it
        mov     %rax, 184(%r12)         # word 23: a pid, or the refusal
        mov     %rax, %r13
        test    %rax, %rax
        jle     done

        mov     %r13, %rdi              # tidy it away again
        mov     $9, %esi
        mov     $62, %eax
        syscall
        mov     %r13, %rdi
        lea     200(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 192(%r12)         # word 24
        movq    $15, 120(%r12)

        # ---- a signal this process sends itself, and catches ----
        #
        # **RFC 0083.** Every act above ends a process; this one does not. The
        # handler runs on the way out of the very `kill` that raised it --
        # there is no wake and no park, because the target is this process and
        # it is already inside the adapter making the call.
        #
        # `SA_RESTORER`, and the restorer is not optional: the frame this
        # personality builds puts the restorer's address where a `ret` will
        # find it, so a handler that returns lands there and the restorer's
        # `rt_sigreturn` is what puts the interrupted registers back.
        lea     caught(%rip), %rax
        mov     %rax, 0x40000040
        movq    $0x04000000, 0x40000048         # SA_RESTORER
        lea     restorer(%rip), %rax
        mov     %rax, 0x40000050
        movq    $0, 0x40000058

        mov     $15, %edi                       # rt_sigaction(SIGTERM, &act, 0, 8)
        mov     $0x40000040, %esi
        xor     %edx, %edx
        mov     $8, %r10d
        mov     $13, %eax
        syscall
        mov     %rax, 208(%r12)         # word 26
        movq    $16, 120(%r12)
        test    %rax, %rax
        jnz     done

        mov     (%r12), %rdi                    # kill(self, SIGTERM)
        mov     $15, %esi
        mov     $62, %eax
        syscall
        mov     %rax, 216(%r12)         # word 27: what the kill answered
        movq    $17, 120(%r12)

        # ---- a child parked in a call, woken to catch it ----
        #
        # The half a self-signal cannot reach: the target is asleep *inside* a
        # system call, which is where a shell waiting for a key is. It is woken
        # by the `kill`, re-enters the adapter, and its `nanosleep` is
        # interrupted -- the handler runs and exits 88, so its parent collects
        # an ordinary exit rather than a death by signal. That difference is
        # the whole assertion: without delivery this child would be status 15.
        # **A stack for the child, because a signal frame is built on one.**
        #
        # A forked child is started on its *parent's* `rsp`, and a fork copies
        # the regions the personality recorded -- what `mmap` answered. The
        # program's original stack is not one of those, so the child's `rsp`
        # points at memory its own address space does not have. It can run
        # (`nanosleep` touches no stack) and it cannot be *signalled*: the
        # delivery writes a `siginfo` and a `ucontext` below `rsp`, and the
        # copy fails. The adapter counted exactly that -- one frame it could
        # not build -- which is how this was found rather than guessed.
        #
        # So the child stands on a page that was mapped before the fork and
        # therefore exists on both sides of it.
        mov     $0x40020000, %edi
        mov     $4096, %esi
        mov     $3, %edx
        mov     $0x32, %r10d
        mov     $-1, %r8
        xor     %r9d, %r9d
        mov     $9, %eax
        syscall
        cmp     $0x40020000, %rax
        jne     done

        # **The handler the child will have, installed before the fork.**
        #
        # A child inherits its parent's dispositions -- RFC 0083 made that true
        # here, as it is on Linux -- so installing it now is what removes a race
        # this probe found the hard way: a child that installed its own handler
        # after `fork` could be killed before it got there, and the run then
        # showed a death by signal 15 on one boot and an uncaught return on the
        # next. Installed before the fork there is no window at all.
        #
        # It points into the *copied* page, because a child's instruction
        # pointer has to land somewhere the fork carried over.
        lea     (child_handler - inner)(%r15), %rax
        mov     %rax, 0x40000040
        movq    $0, 0x40000048          # flags: it never returns, so no restorer
        movq    $0, 0x40000050
        movq    $0, 0x40000058

        mov     $15, %edi               # rt_sigaction(SIGTERM, &act, 0, 8)
        mov     $0x40000040, %esi
        xor     %edx, %edx
        mov     $8, %r10d
        mov     $13, %eax
        syscall
        test    %rax, %rax
        jnz     done

        lea     (catch_park - inner)(%r15), %rax
        call    *%rax
        mov     %rax, 224(%r12)         # word 28: the child's pid
        mov     %rax, %r13
        movq    $18, 120(%r12)
        test    %rax, %rax
        jle     done

        mov     %r13, %rdi                      # kill(child, SIGTERM)
        mov     $15, %esi
        mov     $62, %eax
        syscall
        mov     %rax, 232(%r12)         # word 29
        movq    $19, 120(%r12)

        mov     %r13, %rdi                      # wait4(child, &status, 0, 0)
        lea     248(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 240(%r12)         # word 30, and word 31 is the status
        movq    $20, 120(%r12)

        # ---- a child parked on a pipe that will never be written ----
        #
        # **The act that reaches the other delivery path.** A woken
        # `nanosleep` *completes* -- the adapter sees the deadline was taken
        # and answers it -- so the act above is delivered on a finished call.
        # A `read` on an empty pipe does not: woken, re-asked, still empty, it
        # parks again. Without an arm that interrupts a call which is about to
        # park, this child would be woken and re-parked for ever with its
        # signal still pending, and the wake would be burned. That is the shape
        # a shell blocked on a key is in.
        #
        # pipe2(&fds, 0): the read end lands at 0x40000060, the write end four
        # bytes after it, and the fork copies both.
        mov     $0x40000060, %edi
        xor     %esi, %esi
        mov     $293, %eax
        syscall
        mov     %rax, 280(%r12)         # word 35
        movq    $21, 120(%r12)
        test    %rax, %rax
        jnz     done

        lea     (pipe_park - inner)(%r15), %rax
        call    *%rax
        mov     %rax, 288(%r12)         # word 36: the child's pid
        mov     %rax, %r13
        movq    $22, 120(%r12)
        test    %rax, %rax
        jle     done

        mov     %r13, %rdi              # kill(child, SIGTERM)
        mov     $15, %esi
        mov     $62, %eax
        syscall
        mov     %rax, 296(%r12)         # word 37
        movq    $23, 120(%r12)

        mov     %r13, %rdi              # wait4(child, &status, 0, 0)
        lea     312(%r12), %rsi
        xor     %edx, %edx
        xor     %r10d, %r10d
        mov     $61, %eax
        syscall
        mov     %rax, 304(%r12)         # word 38, and word 39 is the status
        movq    $24, 120(%r12)

        movq    $0xC0FFEE, 88(%r12)     # word 11: every step above ran
done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .

        # **The handler itself** -- RFC 0083. It runs in the parent, which
        # keeps its whole address space across a fork, so unlike everything
        # below it needs no copied page.
        #
        # `%r12` is still the report page: a delivery edits `rdi`, `rsi`, `rdx`,
        # `rip` and `rsp` and leaves every other register alone, which is what
        # lets a handler write where the rest of the program writes.
caught:
        movq    $0xCA7, 256(%r12)       # word 32: the handler ran
        mov     %rdi, 264(%r12)         # word 33: the signal it was handed
        incq    272(%r12)               # word 34: and how many times
        ret                             # to the restorer the frame put here

        # What a handler returns through. `rt_sigreturn` takes no arguments and
        # never comes back.
restorer:
        mov     $15, %eax
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
        # A child that parks in a call with a handler it inherited -- RFC 0083.
        #
        # **It installs nothing**, and that is the assertion underneath this
        # act: the handler is its parent's, carried across the `fork` the way
        # Linux carries one. It parks, is woken by a `SIGTERM` it never asked
        # for, and its inherited handler ends it with a code of its own.
catch_park:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      6f
        ret
6:      mov     $0x40020ff0, %esp       # a stack this address space actually has
        mov     $0x40000000, %edi       # nanosleep(&{1000, 0}, NULL)
        xor     %esi, %esi
        mov     $35, %eax
        syscall
        # Reached only if the sleep returned without the handler ending this
        # process -- so the exit code says "the call came back and nothing
        # caught the signal", which the parent can tell from 88.
        mov     $99, %edi
        mov     $231, %eax
        syscall
        jmp     .

        # A child that parks on a pipe nobody will write to. Unlike the sleeper
        # above, its call **re-parks** when it is woken, so it is delivered to
        # by the arm that interrupts a call about to block rather than by the
        # one that rides out on a finished call.
pipe_park:
        mov     $57, %eax               # fork
        syscall
        test    %rax, %rax
        jz      7f
        ret
7:      mov     $0x40020ff0, %esp       # a stack this address space has
        mov     0x40000060, %edi        # the read end its parent made
        mov     $0x40000080, %esi       # somewhere to put a byte
        mov     $1, %edx
        xor     %eax, %eax              # read
        syscall
        # Reached only if the read returned without the handler ending this
        # process, which the parent tells from 88.
        mov     $97, %edi
        mov     $231, %eax
        syscall
        jmp     .

        # The child's handler, which does not return: it ends the process with
        # a code of its own, so the parent's `wait4` sees an *exit* where a
        # child with no handler would have shown a death by signal 15.
child_handler:
        mov     $88, %edi
        mov     $231, %eax              # exit_group(88)
        syscall
        jmp     .
inner_end:
