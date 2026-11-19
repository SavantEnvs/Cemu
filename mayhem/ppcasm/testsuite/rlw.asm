rlwinm r3, r4, 2, 0, 29
cmpwi r3, 0
bne- 0x02000008
lwz r3, 0(r3)
mtctr r12
bctr
