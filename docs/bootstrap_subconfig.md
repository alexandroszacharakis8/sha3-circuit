# Bootstrapping subconfig

This config is tasked with taking a spread word that has accumulated error and computing a fresh *bootstraped* spread word that has no errors. Recall that a spread word can be written as 3 spread words corresponding to the least significant, middle and most significant bits. To bootstrap a spread word $w$, we express it as three words $w_H, w_M, w_L$ and show that these are the parts of $w$ by asserting that $w = w_L + 2w_M + 4w_H$. Then we output one of this words depending on the operation that lead to $w$. For example, for XORing words we output $w_L$.

The words $w_L, w_M, w_H$ are asserted via the [decomposition subconfig](decomposition_subconfig.md) and then simple constrains assert the relation of these with $w$. 

Note that if we know that $w_H=0$ we can omit the term $4w_H$. This is the case when the operations we have performed to construct $w$ do not have accumulation error that can affect the high bits (these operations are always part of the circuit description).

## Implementing the constraints

We simply need a single constraint -handled by the `q_bootstrap` selector- to assert computations of the form $acc' = 2\cdot acc + w$. The layout looks like this (X denotes unused values):

| res      |  acc    
|----------|----------
|     X    |  acc
|     p    |  acc'

and the enforced constraints is $acc(\omega X) = 2\cdot acc(X) + res(\omega X)$. Two consecutive bootstrapping constraints are enough to assert the equation $w = w_L + 2w_M + 4w_H$.  

## The layout

There are two cases: either $w_H = 0$ or not. The first case is simpler to handle and only requires 2 rows while the second requires 3 rows. We present only the most complex of the two. In what follows, we write the limbs (which are handled by the [decomposition subconfig](decomposition_subconfig.md)) together as $l$ for ease of presentation.

The circuit layout for bootstraping a word looks as follows:  

|offset| res |  acc   |   limbs     |
|------|-----|--------|-------------|
|   0  |  a  |  acc0  |  ...l_a...  |
|   1  |  b  |  acc1  |  ...l_b...  |
|   2  |  c  |  acc2  |  ...l_c...  |
    
and the constrains that are applied are: 

1. $a$ is a valid spread word (via limb decomposition $l_a$)
2. $b$, is a valid spread word (via limb decomposition $l_b$)
3. $c$, is a valid spread word (via limb decomposition $l_c$)
4. $acc_1 = b + 2 acc_0$ ($b + 2a$)
5. $acc_2 = c + 2 acc_1$ ($c + 2b + 4acc0 = c + 2b + 4a$)
6. $acc_0 = a$ (equality constraint)

The first three are handled by the `q_spread` and `q_dc` selectors of the [decomposition subconfig](decomposition_subconfig.md) which are enabled on all rows and the constraints 4, 5 are handled by the `q_bootstrap` selector on rows 0, 1.

**Note:** the above constraints guarantees that $acc_2 = c + 2b + 4a$, where $a,b,c$ are spread words *with no errors*. It is always the case that $acc_2$ is also a spread word (with errors). Note that the latter value *is not copy-constraint* although the goal is to bootstrap this value. The reason is that $acc_2$ is *further constraint* by the [auxiliary linear combination subconfig](aux_lc_subconfig.md) to be the result of one of the operations of the Keccak-f function. 
