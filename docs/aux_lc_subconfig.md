# Auxiliary linear combination subconfig

This config computes the various linear combinations (on spread bits) needed for the keccak operations. More concretely, 
it computes 

1. A linear combination to compute the values $C_i$ by adding the state elements $\sum_j A_{i,j}$ where also the round constant 
of the previous round is added: 

$$ C_i = \sum_j A_{i,j} + r $$

2. A linear combination to compute the state after applying the $\theta$ step and add the round constant of the previous round for the case of $A_{0,0}$. 
Concretly, it performs the computation: 

$$ A^\theta_{i,j} = C_{i-1} + rot(C_{i+1},1) + A_{i,j} + r $$ 

3. A linear combination to compute the result of the $\chi$ function and optionally absorb a message part:

$$ A^\chi_{i,j} = 2A_{i,j} + (\textasciitilde ones - A_{i+1,j}) + A_{i+2,j} + 2M_{j + 5i} $$

In the above, $ones = 2^{64} - 1$, i.e. it is the 64 lane which has all its bits equal to one.

Check the [keccak operations subconfig](keecak_operations_subconfig.md) to see why this operations on spread bits correspond to the dense operations done by the 
keccak-f function.

## Implementing the constraints

The constraints are straight-forward to implement by simple field operations. We describe the next for completeness:

### LC for computing c

This is handled by the `q_c` selector which on a layout looking as follows (X denotes unused cells): 

| q_c | aux0     | aux1     | acc     |
|-----|----------|----------|---------|
|  1  |    a0    |    a1    |    X    |
|  0  |    a2    |    a3    |    X    |
|  0  |    a4    |    rc    |   res   |

adds the constraint 

$$ acc(\omega^2 X) = aux_0(X) + aux_1(X) + aux_0(\omega X) + aux_1(\omega X) + aux_0(\omega^2 X) + aux_1(\omega^2 X) $$

### LC for computing $\theta, \iota$

This is handled by the `q_theta` (= `q_iota`) selector which on a layout looking as follows (X denotes unused cells): 

| q_theta | aux0     | aux1     | acc     |
|---------|----------|----------|---------|
|  1      |    a0    |    a1    |    X    |
|  0      |    a2    |    a3    |    res  |

adds the constraint 

$$ acc(\omega X) = aux_0(X) + aux_1(X) + aux_0(\omega X) + aux_1(\omega X) $$

We use the same constaint for the $\theta, \iota$ step which need to do the same linear combination. In particular the two 
selectors are the same.


### LC for computing $\chi$

This is handled by the `q_chi` selector which on a layout looking as follows (X denotes unused cells): 

| q_chi   | aux0     | aux1     | acc     |
|---------|----------|----------|---------|
|  1      |   a      |    c     |    X    |
|  0      |   b      |    d     |    res  |

adds the constraint 

$$ acc(\omega X) = 2(aux_0(X) + aux_1(X)) + \textasciitilde ones - aux_0(\omega X) + aux_1(\omega X) $$
