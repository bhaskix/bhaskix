        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards.
        #
        # RFC 0005 step 6: **a futex under contention.** The RFC's reason for
        # asking: a subtly wrong futex does not produce an error, it produces a
        # program that deadlocks under contention, occasionally, on a machine
        # with more cores than the one it was tested on. Every other futex
        # probe here pairs one sleeper with one waker. This one runs four
        # threads -- this one and three it clones with glibc's
        # `pthread_create` flags, which the kernel starts on CPUs in rotation
        # -- through two phases, and then joins the three as glibc's
        # `pthread_join` does.
        #
        # **The lock.** Drepper's mutex from "Futexes Are Tricky" (his second):
        # 0 free, 1 held, 2 held with waiters, taken with `cmpxchg` and `xchg`,
        # let go with `lock dec`, sleeping and waking one with the private
        # operations glibc's mutex uses. Inside it a counter is read, a
        # `sched_yield` made on every fourth pass -- so the holder is off its
        # CPU while the others try the lock, and contention is not left to
        # luck -- and the counter written back one higher. The counter is plain
        # memory, so a lock that admitted two holders would lose counts. 500
        # passes a thread.
        #
        # **What the lock cannot see is a lost wake**, and that is why there is
        # a second phase. A waiter that sleeps through its wake is woken by the
        # next contended unlock, so a mutex under contention rescues it; only a
        # wake lost at the very end would ever be seen. Measured, not argued:
        # with the adapter's compare-before-park removed, the lock alone came
        # through 8,000 passes untouched (2026-11-11, an earlier version of
        # this probe that was only the lock).
        #
        # **The ring.** One turn word, and four threads that take turns by it:
        # thread i waits while the turn, modulo four, is not i; on its turn it
        # moves the turn on by one and wakes every sleeper on the word. Nobody
        # else can move the turn, so a wake lost here stops the ring at once,
        # and the probe never says it finished. 125 turns a thread.
        #
        # The page, in words: 0 one once done; 1 the lock's counter; 2 clones
        # made; 3 the last clone answer; 4 joins that ended because the
        # thread's tid word was cleared; 5 the waits those joins made; 6 the
        # tid words after the joins, or-ed (0); 7 threads through the lock;
        # 8 the turn after the ring; 9 threads through the ring; 10 clones
        # refused with EAGAIN and asked again. Words 16-79
        # are four blocks of sixteen, one a thread, at 0x80 + 0x80 * its index:
        # the lock's passes, waits, waits answered 0, waits answered EAGAIN,
        # wakes, threads those woke; other answers and the last of them; then
        # the ring's turns, waits, waits answered 0, waits answered EAGAIN,
        # wakes, threads those woke. The lock word is at 0x400, thread i's tid
        # word at 0x400 + 0x40 * i, and the turn word at 0x500.
_start:
        mov     %rdi, %r15              # the report page
        movl    $0, 0x400(%r15)         # the lock: free
        movl    $0, 0x500(%r15)         # the turn: thread 0's
        mov     $1, %r14d               # the first thread to clone
clone_next:
        # clone(0x3d0f00, stack, &tid, &tid, tls), thread r14 of three
        mov     %r14, %rax
        shl     $6, %rax
        lea     0x400(%r15,%rax), %rdx  # CLONE_PARENT_SETTID
        mov     %rdx, %r10              # CLONE_CHILD_CLEARTID: the same word
        mov     %r14, %rax
        shl     $8, %rax
        lea     0x700(%r15,%rax), %r8   # a TLS base nothing reads
        mov     %r14, %rax
        shl     $12, %rax
        mov     %rsp, %rsi
        sub     %rax, %rsi              # its stack, 0x1000 a thread below this one
        and     $-16, %rsi
        mov     $0x3d0f00, %edi
        mov     $56, %eax               # clone
        syscall
        test    %rax, %rax
        jz      worker                  # the new thread, with its index in r14
        # A clone refused with EAGAIN is counted, yielded on and asked again,
        # up to a thousand times in all, as Go's runtime asks again; the
        # kernel requires the count to be zero, so a refusal is still a
        # failure -- but one that says what it was rather than leaving the
        # ring to wait for a thread that never existed.
        cmp     $-11, %rax
        jne     2f
        incq    0x50(%r15)              # clones refused
        cmpq    $1000, 0x50(%r15)
        jae     2f
        mov     $24, %eax               # sched_yield
        syscall
        jmp     clone_next
2:
        mov     %rax, 0x18(%r15)        # the last clone answer
        js      1f
        incq    0x10(%r15)              # a clone made
1:
        inc     %r14
        cmp     $4, %r14
        jb      clone_next
        xor     %r14d, %r14d            # this thread is thread 0

worker:
        mov     %r14, %rbx
        shl     $7, %rbx
        lea     0x80(%r15,%rbx), %rbx   # this thread's block
        xor     %r12d, %r12d            # passes made
pass:
        # Lock: 0 -> 1 if free; otherwise mark it 2 and sleep while it is 2.
        xor     %eax, %eax
        mov     $1, %ecx
        lock cmpxchg %ecx, 0x400(%r15)
        jz      locked
        cmp     $2, %eax
        je      wait
        mov     $2, %eax
        xchg    %eax, 0x400(%r15)
        test    %eax, %eax
        jz      locked
wait:
        lea     0x400(%r15), %rdi
        mov     $128, %esi              # FUTEX_WAIT_PRIVATE
        mov     $2, %edx                # sleep only while it reads 2
        xor     %r10d, %r10d            # no timeout
        mov     $202, %eax              # futex
        syscall
        incq    8(%rbx)                 # waits
        test    %rax, %rax
        jnz     1f
        incq    16(%rbx)                # slept, and was woken
        jmp     2f
1:
        cmp     $-11, %rax
        jne     3f
        incq    24(%rbx)                # EAGAIN: the word had moved
        jmp     2f
3:
        incq    48(%rbx)                # anything else is a defect
        mov     %rax, 56(%rbx)
2:
        mov     $2, %eax
        xchg    %eax, 0x400(%r15)
        test    %eax, %eax
        jnz     wait
locked:
        # Held: the counter read, a yield on every fourth pass, the counter
        # written back one higher.
        mov     8(%r15), %r13
        inc     %r13
        test    $3, %r12d
        jnz     4f
        mov     $24, %eax               # sched_yield
        syscall
4:
        mov     %r13, 8(%r15)
        # Unlock: 1 -> 0 means nobody waits; otherwise free it and wake one.
        lock decl 0x400(%r15)
        jz      unlocked
        movl    $0, 0x400(%r15)
        lea     0x400(%r15), %rdi
        mov     $129, %esi              # FUTEX_WAKE_PRIVATE
        mov     $1, %edx                # one
        mov     $202, %eax              # futex
        syscall
        incq    32(%rbx)                # wakes
        test    %rax, %rax
        js      5f
        add     %rax, 40(%rbx)          # threads they woke
        jmp     unlocked
5:
        incq    48(%rbx)
        mov     %rax, 56(%rbx)
unlocked:
        inc     %r12
        mov     %r12, (%rbx)            # passes made
        cmp     $500, %r12
        jb      pass
        lock incq 0x38(%r15)            # a thread through the lock

        # The ring: wait while the turn is not this thread's, then move it on
        # and wake every sleeper on it.
        xor     %r12d, %r12d            # turns taken
turn:
        mov     0x500(%r15), %edx       # the turn now, which is what a wait expects
        mov     %edx, %eax
        and     $3, %eax
        cmp     %r14d, %eax
        je      mine
        lea     0x500(%r15), %rdi
        mov     $128, %esi              # FUTEX_WAIT_PRIVATE
        xor     %r10d, %r10d
        mov     $202, %eax              # futex
        syscall
        incq    72(%rbx)                # ring waits
        test    %rax, %rax
        jnz     1f
        incq    80(%rbx)                # slept, and was woken
        jmp     turn
1:
        cmp     $-11, %rax
        jne     3f
        incq    88(%rbx)                # EAGAIN: the turn had moved
        jmp     turn
3:
        incq    48(%rbx)                # anything else is a defect
        mov     %rax, 56(%rbx)
        jmp     turn
mine:
        inc     %edx
        mov     %edx, 0x500(%r15)       # only the thread whose turn it is writes it
        lea     0x500(%r15), %rdi
        mov     $129, %esi              # FUTEX_WAKE_PRIVATE
        mov     $0x7fffffff, %edx       # all of them: only one is next
        mov     $202, %eax              # futex
        syscall
        incq    96(%rbx)                # ring wakes
        test    %rax, %rax
        js      5f
        add     %rax, 104(%rbx)         # threads they woke
        jmp     6f
5:
        incq    48(%rbx)
        mov     %rax, 56(%rbx)
6:
        inc     %r12
        mov     %r12, 64(%rbx)          # turns taken
        cmp     $125, %r12
        jb      turn
        lock incq 0x48(%r15)            # a thread through the ring
        test    %r14, %r14
        jz      join_all
        xor     %edi, %edi
        mov     $60, %eax               # exit: this thread only
        syscall
        jmp     .

join_all:
        # pthread_join, three times: while a thread's tid word is not zero, a
        # shared FUTEX_WAIT on it, bounded at 100,000 waits a thread.
        mov     $1, %r14d
join_next:
        mov     %r14, %rax
        shl     $6, %rax
        lea     0x400(%r15,%rax), %r13  # its tid word
        xor     %r12d, %r12d
join:
        mov     (%r13), %edx            # expected: what the word holds now
        test    %edx, %edx
        jz      joined
        mov     %r13, %rdi
        xor     %esi, %esi              # FUTEX_WAIT, not private
        xor     %r10d, %r10d
        mov     $202, %eax              # futex
        syscall
        incq    0x28(%r15)              # join waits
        inc     %r12
        cmp     $100000, %r12
        jb      join
        jmp     7f                      # gave up: not a join
joined:
        incq    0x20(%r15)
7:
        mov     (%r13), %eax
        or      %rax, 0x30(%r15)        # the word after the join
        inc     %r14
        cmp     $4, %r14
        jb      join_next
        mov     0x500(%r15), %eax
        mov     %rax, 0x40(%r15)        # the turn after the ring
        movq    $1, (%r15)              # done; the kernel reads the page and ends this
        jmp     .
