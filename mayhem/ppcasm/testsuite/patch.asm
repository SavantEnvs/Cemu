li r3, 5
addi r4, r3, -1
mflr r0
stw r0, 4(r1)
lis r5, 0x1234
ori r5, r5, 0x5678
fmuls f1, f2, f3
bl 0x02000100
beq cr0, 0x02000020
.float 1.5
.int 0x12345678
blr
