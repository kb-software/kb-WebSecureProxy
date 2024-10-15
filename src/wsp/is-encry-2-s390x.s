### Assembler ##############
# Assembler: 
# Reference version: 
# Recommended flags:
##############################

.global m_impl_add
.global m_impl_sub
.global m_impl_add_karatsuba
.global m_impl_sub_karatsuba
.global m_impl_cmp
.global m_impl_mult_basic
.global m_impl_square
.global m_impl_add_word
.global m_impl_mont_mul_add
.global m_impl_first_bit
.global m_impl_last_bit

### General note #####################
# Input parameters      r2, r3, ...
# Return value          r2 
###################################### 

# Addition
# r2        dst
# [r3,r4]   num1
# [r5,r6]   num2
m_impl_add:
    stg     %r6, 48(%r15)       # push r6
    srlg    %r4, %r4, 3
    srlg    %r6, %r6, 3         # byte2word
    lgr     %r1, %r6
    slr     %r1, %r4
    brc     3, end_sort_add     # If r6 >= r4, skip sort
    lgr     %r1, %r3
    lgr     %r3, %r5
    lgr     %r5, %r1
    lgr     %r1, %r4
    slr     %r1, %r6
    lgr     %r4, %r6
end_sort_add:
    ltgfr   %r4, %r4            # r4    min of inpt sizes
    llgfr   %r6, %r1            # r6    diff of inpit sizes
    brc     7, begin_main_add   # Test if r4 > 0
    sgr     %r1, %r1
    lhi     %r3, -1
    brc     15, loop_carry_add
begin_main_add: 
    sgr     %r1, %r1            # r1 = 0 and clear carry
loop_main_add:
    lg      %r0, 0(%r1,%r5)
    alcg    %r0, 0(%r1,%r3)
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brctg   %r4, loop_main_add  # END loop_main
    lhi     %r3, -1             # r3 loop bound as well as increment
loop_carry_add:                 # i.e. do{r6+=r3 ...}while(r6>r3)
    brxle   %r6, %r3, last_carry_add
    lg      %r0, 0(%r1,%r5)
    alcgr   %r0, %r4
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brc     15, loop_carry_add  # END loop_carry
last_carry_add:
    alcgr   %r4, %r4            # Last carry
    stg     %r4, 0(%r1,%r2)
    llgfr   %r2, %r1
    srl     %r2, 3
    algr    %r2, %r4            # Inc if last carry != 0
    lg      %r6, 48(%r15)       # pop r6
    sllg    %r2, %r2, 3         # word2byte
    br      %r14                # END m_impl_add

# Subtraction
# r2        dst
# [r3,r4]   num1
# [r5,r6]   num2
m_impl_sub:
    stg     %r6, 48(%r15)       # push r6
    srlg    %r4, %r4, 3
    srlg    %r6, %r6, 3         # byte2word
    slr     %r4, %r6
    slgr    %r1, %r1            # r1 = 0, borrow = 0
    brxle   %r6, %r1, borrow_check_sub
loop_main_sub:                  # (Note r6 > 0)
    lg      %r0, 0(%r1,%r3)
    slbg    %r0, 0(%r1,%r5)
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brct    %r6, loop_main_sub  # END loop_main
borrow_check_sub:
    lhi     %r5, -1             # r5 loop bound as well as increment
    llgfr   %r6, %r6            # r6 = 0
loop_borrow_sub:                # (Note r4 >= 0)
    brxle   %r4, %r5, size_check_sub
    lg      %r0, 0(%r1,%r3)
    slbgr   %r0, %r6
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brc     15, loop_borrow_sub # END loop_borrow
size_check_sub: 
    lhi     %r5, -8
loop_size_sub:
    brxle   %r1, %r5, end_sub
    ltg     %r0, 0(%r1,%r2)
    brc     6, end_sub          # If r0 != 0, done
    brc     15, loop_size_sub
end_sub:
    ahi     %r1, 8
    llgfr   %r2, %r1
    srl     %r2, 3
    lg      %r6, 48(%r15)       # pop r6
    sllg    %r2, %r2, 3         # word2byte
    br      %r14                # END m_impl_sub
    
# Add karatsuba
# r2    dst
# r3    a
# r4    b
# r5    len
m_impl_add_karatsuba:
    srlg    %r5, %r5, 3         # byte2word
    sgr     %r1, %r1            # r1 = 0 and clear carry
    brxle   %r5, %r1, end_ak    # If r5 = 0, done
loop_ak:
    lg      %r0, 0(%r1,%r3)
    alcg    %r0, 0(%r1,%r4)
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brct    %r5, loop_ak
end_ak: 
    alcr    %r5, %r5
    llgfr   %r2, %r5
    br      %r14

# Sub karatsuba
# r2    dst
# r3    a
# r4    b
# r5    len
m_impl_sub_karatsuba:
    srlg    %r5, %r5, 3         # byte2word
    slgr    %r1, %r1            # r1 = 0 and clear borrow
    brxle   %r5, %r1, end_sk    # If r5 = 0, done
loop_sk:
    lg      %r0, 0(%r1,%r3)
    slbg    %r0, 0(%r1,%r4)
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brct    %r5, loop_sk
end_sk:
	lghi    %r2, 0
    lghi    %r3, 1
    locgr   %r2, %r3, 12
    br      %r14
    
# Compare
# r2    a
# r3    b
# r4    len
m_impl_cmp:
    srlg    %r4, %r4, 3         # byte2word
    ltgfr   %r1, %r4
    sll     %r1, 3
    lhi     %r5, -8
loop_cmp:
    brxle   %r1, %r5, end_cmp
    lg      %r0, 0(%r1,%r2)
    clg     %r0, 0(%r1,%r3)
    brc     8, loop_cmp
end_cmp:
    lghi    %r2, 0
    lghi    %r3, 1
    lghi    %r4, -1
    locgr   %r2, %r3, 2
    locgr   %r2, %r4, 4
    br      %r14

# Add word
# r2  a
# r3  word
m_impl_add_word:
    sgr     %r1, %r1
loop_adw:
    lg      %r0, 0(%r1,%r2)     # To be simplifies as 0(%r1,0)
    alcgr   %r0, %r3
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brc     3, loop_adw
    br      %r14

# Mult (school book)
# r2        dst
# [r3,r4]   a
# [r5,r6]   b
m_impl_mult_basic: 
    stmg    %r6, %r10, 48(%r15)     # push r6
    srlg    %r4, %r4, 3
    srlg    %r6, %r6, 3             # byte2word
    xgr     %r0, %r0
    xgr     %r1, %r1
    llgfr   %r7, %r4
loop_zero_mul:
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brctg   %r7, loop_zero_mul
loop_outer_mul:
    lg      %r0, 0(%r5,0)           # r0 word multiplier
    xgr     %r1, %r1                # r1 off set
    sgr     %r10, %r10              # r10 carry = 0, cflag = 0
    llgfr   %r7, %r4
loop_inner_mul:
    lgr     %r9, %r0
    mlg     %r8, 0(%r1,%r3)
    alcgr   %r9, %r10
    lghi    %r10, 0
    alcgr   %r10, %r8               # New carry
    alg     %r9, 0(%r1,%r2)
    stg     %r9, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brctg   %r7, loop_inner_mul
    alcgr   %r10, %r7
    stg     %r10, 0(%r1,%r2)        # Last carry
    la      %r2, 8(%r2,0)
    la      %r5, 8(%r5,0)
    brctg   %r6, loop_outer_mul
    lmg     %r6, %r10, 48(%r15)     # pop r6
    br      %r14

# Squaring
# r2        dst
# [r3,r4]   a
m_impl_square:
    stmg    %r6, %r15, 48(%r15)
    lgr     %r5, %r3
    lgr     %r6, %r4
    aghi    %r15, -160
    brasl   %r14, m_impl_mult_basic
    lmg     %r6, %r15, 208(%r15)
    br      %r14

# Montgomery helper function
# r2        dst
# r3        -m[0]^{-1}
# [r4,r5]   m
# r6        src
m_impl_mont_mul_add:  
    stmg    %r6, %r10, 48(%r15) # push r6
    srlg    %r5, %r5, 3         # byte2word
    sgr     %r1, %r1
    llgfr   %r7, %r5
    sll     %r7, 1
loop_cpy_mma:
    lg      %r0, 0(%r1,%r6)
    stg     %r0, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brct    %r7, loop_cpy_mma
    xgr     %r0, %r0
    stg     %r0, 0(%r1,%r2)     # insert 0 to the last position
    llgfr   %r6, %r5            # r6    ctr_outer
loop_outer_mma:
    lgr     %r9, %r3
    mlg     %r8, 0(%r2,0)
    lgr     %r0, %r9            # r0    multiplier
    llgfr   %r7, %r5            # r7    ctr_inner
    xgr     %r1, %r1            # r1    offset
    sgr     %r10, %r10          # r10   carry, cflag = 0
loop_inner_main_mma:
    lgr     %r9, %r0
    mlg     %r8, 0(%r1,%r4)
    alcgr   %r9, %r10
    lghi    %r10, 0
    alcgr   %r10, %r8           # new carry
    alg     %r9, 0(%r1,%r2)
    stg     %r9, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brctg   %r7, loop_inner_main_mma
    alcgr   %r10, %r7
    alcg    %r10, 0(%r1,%r2)
    stg     %r10, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
loop_inner_carry_mma:
    brc     12, end_inner_carry_mma
    lghi    %r10, 0
    alcg    %r10, 0(%r1,%r2)
    stg     %r10, 0(%r1,%r2)
    la      %r1, 8(%r1,0)
    brc     15, loop_inner_carry_mma
end_inner_carry_mma:  
    la      %r2, 8(%r2,0)
    brct    %r6, loop_outer_mma
    lmg     %r6, %r10, 48(%r15) # pop r6
    br      %r14

m_impl_first_bit:
    lgr     %r5, %r2
    lghi    %r2, 0
    lghi    %r1, 63
loop_fb:
    sllg    %r4, %r5, 0(%r1)
    ltgr    %r4, %r4
    jne	    end_fb
    aghi    %r2, 1
    brctg   %r1, loop_fb
end_fb:
    br      %r14


m_impl_last_bit:
    lgr     %r5, %r2
    lghi    %r2, 63
loop_lb:
    srlg    %r4, %r5, 0(%r2)
    ltgr    %r4, %r4
    jne	    end_lb
    brctg   %r2, loop_lb
end_lb:
    br	    %r14
