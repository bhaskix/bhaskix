        .text
        .globl _start
_start:
        mov     %rdi, %r12              # the buffer page
        mov     %rsi, %r14              # the names, kept across the calls
        mov     %rsi, %rdi              # "/"
        xor     %esi, %esi              # O_RDONLY
        xor     %edx, %edx
        mov     $2, %eax                # open
        syscall
        test    %rax, %rax
        js      done
        mov     %rax, %r13              # the directory descriptor

        # 1. getdents64(dirfd, buffer, 256), then print the first name
        mov     %r13, %rdi
        mov     %r12, %rsi
        mov     $256, %edx
        mov     $217, %eax
        syscall
        test    %rax, %rax
        jle     done
        call    say

        # 2. lseek(dirfd, 0, SEEK_SET) -- rewinddir -- then list again. Without
        #    the seek the listing is spent and getdents64 answers nothing.
        mov     %r13, %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        mov     $8, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     %r13, %rdi
        mov     %r12, %rsi
        mov     $256, %edx
        mov     $217, %eax
        syscall
        test    %rax, %rax
        jle     done
        call    say

        # 3. fstat(dirfd, buffer + 512), and print only if st_mode says this is
        #    a directory -- so a mode written to the wrong offset stops here.
        lea     512(%r12), %rsi
        mov     %r13, %rdi
        mov     $5, %eax
        syscall
        test    %rax, %rax
        js      done
        mov     536(%r12), %eax         # st_mode, at offset 24 of the stat
        and     $0xf000, %eax
        cmp     $0x4000, %eax           # S_IFDIR
        jne     done
        call    say

        # 4. close(dirfd), then open("inner"). Reaching the print is the close
        #    guard: the directory's handle is the adapter's own root
        #    capability, and a close that released it leaves this open with
        #    nothing to find.
        mov     %r13, %rdi
        mov     $3, %eax
        syscall
        lea     2(%r14), %rdi
        xor     %esi, %esi
        xor     %edx, %edx
        mov     $2, %eax
        syscall
        test    %rax, %rax
        js      done
        call    say

done:
        xor     %edi, %edi
        mov     $231, %eax              # exit_group
        syscall
        jmp     .

        # write(1, buffer + 19, 5) -- the name in the first dirent record
say:
        lea     19(%r12), %rsi
        mov     $5, %edx
        mov     $1, %edi
        mov     $1, %eax
        syscall
        ret
