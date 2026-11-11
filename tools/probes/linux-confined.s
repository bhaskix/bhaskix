        .text
        .globl _start
        # rdi = a writable page the kernel reads afterwards; rsi = 1 when the
        # kernel found the adapter holding a directory, 0 when it holds none.
        #
        # RFC 0005's rule 2, **restated for the adapter**. The RFC asked that "a
        # Linux-personality domain holding no filesystem capability must fail
        # every openat, and that test must fail if the personality ever
        # acquires a fallback path". Since RFC 0032 and RFC 0033 the
        # capabilities are bin/linuxd's, not the hosted domain's, so what is
        # tested is what a hosted program can reach through them: when the
        # adapter holds no directory, nothing; when it holds one, what is
        # inside it and nothing above it. Two things are the adapter's own and
        # need no capability -- the generated /proc/self files and the built-in
        # /bin/execed -- and the first is this probe's control: a refusal
        # proves nothing unless the same calls, made the same way, can succeed.
        #
        # **And a name relative to a directory descriptor is resolved in that
        # directory** (2026-11-11): openat with a descriptor for /tmp must find
        # what is in /tmp and not what is in the root -- it found the root's,
        # because the descriptor was ignored -- and a descriptor that is not a
        # directory, or not open, is refused as Linux refuses it. The positive
        # control there is a file this probe makes in /tmp, finds through the
        # descriptor, and removes, on a machine with a disk.
        #
        # Every case stores the answer exactly as it came back, and the kernel
        # holds the table of what each should have been. A case that is not run
        # leaves its bit clear in the mask, so a probe that skipped one cannot
        # look like a probe that was refused it.
        #
        # The page, in words: 0 one once done; 1 the flag as this probe saw it;
        # 2 the mask of cases run; 3 bytes read from /proc/self/status; 4 what
        # its open answered; 5 what the open of the root for the descriptor
        # cases answered; 8 + n case n's answer. Stat results land at 0x800,
        # the /proc read at 0xa00.

        # A case's answer, and its bit in the mask.
        .macro  answered index
        mov     %rax, (64 + 8 * \index)(%r15)
        btsq    $\index, 0x10(%r15)
        .endm

        # A descriptor that came back is closed, so no case leaks one into the
        # next; a refusal is left alone.
        .macro  close_it
        test    %rax, %rax
        js      1f
        mov     %rax, %rdi
        mov     $3, %eax                # close
        syscall
1:
        .endm

        # open(path, flags, mode)
        .macro  open_case index, path, flags, mode=0
        lea     \path(%rip), %rdi
        mov     $\flags, %esi
        mov     $\mode, %edx
        mov     $2, %eax                # open
        syscall
        answered \index
        close_it
        .endm

        # openat(dirfd, path, flags)
        .macro  openat_case index, dirfd, path, flags
        mov     \dirfd, %rdi
        lea     \path(%rip), %rsi
        mov     $\flags, %edx
        xor     %r10d, %r10d
        mov     $257, %eax              # openat
        syscall
        answered \index
        close_it
        .endm

        # stat or lstat(path, buffer)
        .macro  stat_case index, number, path
        lea     \path(%rip), %rdi
        lea     0x800(%r15), %rsi
        mov     $\number, %eax
        syscall
        answered \index
        .endm

        # newfstatat(AT_FDCWD, path, buffer, 0)
        .macro  fstatat_case index, path
        mov     $-100, %rdi
        lea     \path(%rip), %rsi
        lea     0x800(%r15), %rdx
        xor     %r10d, %r10d
        mov     $262, %eax              # newfstatat
        syscall
        answered \index
        .endm

        # access, mkdir, unlink, rmdir: (path, one more word)
        .macro  path_case index, number, path, second=0
        lea     \path(%rip), %rdi
        mov     $\second, %esi
        mov     $\number, %eax
        syscall
        answered \index
        .endm

        # execve(path, {NULL}, {NULL}) -- a success would end this probe, which
        # the kernel reads as a probe that never finished.
        .macro  exec_case index, path
        lea     \path(%rip), %rdi
        lea     empty(%rip), %rsi
        lea     empty(%rip), %rdx
        mov     $59, %eax               # execve
        syscall
        answered \index
        .endm

_start:
        mov     %rdi, %r15              # the report page
        mov     %rsi, %r14              # whether a directory is held
        mov     %r14, 8(%r15)

        # A: names that need the adapter's root. Refused when it holds none;
        # reached when it holds one, which is what shows these calls work.
        open_case    0, p_inner, 0                  # O_RDONLY
        openat_case  1, $-100, p_inner_relative, 0  # AT_FDCWD, relative
        open_case    2, p_root, 0200000             # O_DIRECTORY
        open_case    3, p_dot, 0
        openat_case  4, $-100, p_tmp, 0200000
        stat_case    5, 4, p_root                   # stat
        fstatat_case 6, p_inner
        path_case    7, 21, p_root, 0               # access, F_OK
        path_case    8, 21, p_inner, 4              # access, R_OK

        # B: names beyond any grant. `greeting` is on the same disk, one
        # level above the directory the adapter is given; /bin/execed is a
        # program the adapter carries, which can be run and is not a file.
        open_case    9, p_greeting, 0
        open_case    10, p_up_greeting, 0
        open_case    11, p_sub_inner, 0
        stat_case    12, 6, p_greeting              # lstat
        exec_case    13, p_greeting
        open_case    14, p_execed, 0

        # D: a write outside /tmp, which no capability the adapter holds can
        # carry on any machine.
        open_case    20, p_inner, 1                 # O_WRONLY
        path_case    21, 83, p_made, 0755           # mkdir

        test    %r14, %r14
        jnz     held

        # C: with no directory, the writable names too -- skipped where a
        # directory is held, because there they would change the disk -- and
        # last, an execve of a name that would be a file if there were one.
        open_case    15, p_tmp_file, 01101, 0644    # O_WRONLY|O_CREAT|O_TRUNC
        path_case    16, 83, p_tmp_dir, 0755        # mkdir
        path_case    17, 87, p_tmp_file             # unlink
        path_case    18, 84, p_tmp_dir              # rmdir
        exec_case    19, p_inner
        jmp     control

held:
        # E: through a descriptor for the root, where one can be had.
        lea     p_root(%rip), %rdi
        mov     $0200000, %esi
        xor     %edx, %edx
        mov     $2, %eax                # open
        syscall
        mov     %rax, 0x28(%r15)
        mov     %rax, %r13
        openat_case  22, %r13, p_up_greeting, 0
        openat_case  23, %r13, p_inner_relative, 0
        mov     %r13, %rax
        close_it

        # F: through a descriptor for /tmp -- a directory that is not the
        # root, so a name is resolved in it or not at all. One file is made
        # there to be found through the descriptor, and removed again.
        open_case    27, p_tmp_found, 01101, 0644   # O_WRONLY|O_CREAT|O_TRUNC
        lea     p_tmp(%rip), %rdi
        mov     $0200000, %esi          # O_DIRECTORY
        xor     %edx, %edx
        mov     $2, %eax                # open
        syscall
        answered 26
        mov     %rax, %r12
        openat_case  28, %r12, p_found, 0           # in /tmp: there
        openat_case  29, %r12, p_inner_relative, 0  # in the root, not in /tmp
        openat_case  30, %r12, p_dotdot, 0          # no way up
        openat_case  31, %r12, p_dot, 0             # the directory itself
        mov     %r12, %rax
        close_it
        path_case    32, 87, p_tmp_found            # unlink

control:
        # The adapter's own file, made from its record and stored nowhere.
        lea     p_status(%rip), %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        mov     $2, %eax                # open
        syscall
        mov     %rax, 0x20(%r15)
        mov     %rax, %r13
        test    %rax, %rax
        js      1f
        mov     %r13, %rdi
        lea     0xa00(%r15), %rsi
        mov     $512, %edx
        xor     %eax, %eax              # read
        syscall
        mov     %rax, 0x18(%r15)
1:
        # G, on every machine: a descriptor that is not a directory, one that
        # is not open, and an absolute name, which ignores the descriptor.
        openat_case  24, %r13, p_inner_relative, 0  # /proc/self/status's
        openat_case  25, $99, p_inner_relative, 0   # nothing open there
        openat_case  33, %r13, p_inner, 0           # absolute
        mov     %r13, %rax
        close_it
        movq    $1, (%r15)              # done; the kernel reads the page and ends this
        jmp     .

        # What the calls name: strings, and the empty vector an execve is
        # given. Transcribed as data from here on (tools/probe-bytes.sh).
        .balign 8
probe_data:
empty:
        .quad   0
p_inner:
        .asciz  "/inner"
p_inner_relative:
        .asciz  "inner"
p_root:
        .asciz  "/"
p_dot:
        .asciz  "."
p_dotdot:
        .asciz  ".."
p_tmp:
        .asciz  "/tmp"
p_greeting:
        .asciz  "/greeting"
p_up_greeting:
        .asciz  "../greeting"
p_sub_inner:
        .asciz  "/sub/inner"
p_execed:
        .asciz  "/bin/execed"
p_made:
        .asciz  "/made"
p_tmp_file:
        .asciz  "/tmp/confined"
p_tmp_dir:
        .asciz  "/tmp/confined.d"
p_tmp_found:
        .asciz  "/tmp/confined.found"
p_found:
        .asciz  "confined.found"
p_status:
        .asciz  "/proc/self/status"
