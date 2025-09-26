# Keccak Operations Subconfig

This subconfig uses the other subconfigs to assign the needed values to perform the steps of keccak-f. Here, we explain how each step is done and look into the produced layout and the constraints that occur in each step.

## The $\theta$ step

Recall that to compute the $\theta$ step, given a state $A_{i,j}$ for $i,j\in\{0,..,4\}$ we need to do the following: 

$$ C[i] = A[i,0] \oplus A[i,1] \oplus A[i,2] \oplus A[i,3] \oplus A[i,4] $$

$$ D[i] = C[i-1] \oplus rot(C[i+1,1]) $$

$$ A[i,j] = A[i,j] \oplus D[i] $$

In this step we also do the $\iota$ step of the previous rounds which consists of computing $A^{\iota}[0,0] = A[0,0] \oplus RC$ where $RC$ is the round constant. This is equivalent to XOR-ing the $C[0]$ and new $A[0,0]$ value with $RC$ in the next round. In each of these equations we also XOR with RC or 0 to also handle this part.

### The spread arithmetic constraints

Note that in this step we only perform XOR operations. The corresponding spread arithmetic operation is field addition and the result is on the *least significants bits* of the sum. When we add up to three terms, the high bits are 0 and we can bootstrap in two rows. When we do more (but up to 7 which is the maximum error), we need three rows.

### The layout

We present the layout in two stpes: computing $C$ and then computing the new state. We use the convention that when two values on the layout are the same, a copy-constraint is applied. We 
also state which selectors are enabled in each offset. Cells marked with X denote unused cells.

For computing $C$ the layout looks as follows:

|         selectors                             | offset | dc      |  adv0   |  adv1  |  acc    |   limbs   |
|-----------------------------------------------|--------|---------|---------|--------|---------|-----------|
| `q_spread, q_dc, q_bootstrap, q_c`            |   0    |  ch_0   | a[0,0]  | a[0,1] | ch_0    |    ...    |
| `q_spread, q_dc, q_bootstrap`                 |   1    |  cm_0   | a[0,2]  | a[0,3] | acc0_1  |    ...    |
| `q_spread, q_dc, q_rotation`                  |   2    |  cl_0   | a[0,4]  |   RC   | cerr_0  |    ...    |
|                                               |   3    |  rotc_0 |    X    |   X    |   X     |    ...    |
|                                               |        |   .     |    .    |   .    |   .     |     .     |
|                                               |        |   .     |    .    |   .    |   .     |     .     |
|                                               |        |   .     |    .    |   .    |   .     |     .     |
| `q_spread, q_dc, q_bootstrap, q_c`            |  16    |  ch_4   | a[4,0]  | a[4,1] | ch_4    |    ...    |
| `q_spread, q_dc, q_bootstrap`                 |  17    |  cm_4   | a[4,2]  | a[4,3] | acc4_1  |    ...    |
| `q_spread, q_dc, q_rotation`                  |  18    |  cl_4   | a[4,4]  |   0    | cerr_4  |    ...    |
|                                               |  19    |  rotc_4 |    X    |   X    |   X     |    ...    |

In the above, the following constraints are applied:

1. $cerr_i = \sum_{j=0}^4 a_{i,j} + r$ where $r = RC$ for $i=0$ and 0 otherwise. This is handled by the `q_c` selector of the [auxiliary linear combination subconfig](aux_lc_subconfig.md),
2. $cl_i$ is the bootstrapped value of $cerr_i$. This is handled by the `q_bootstrap` constraint of the [bootstrap subconfig](bootstrap_subconfig.md)  and the `q_spread`, `q_dc` selectors of the [decomposition subconfig](decomposition_subconfig.md),
3. the state values $a_{i,j}$ and $r$ (which is either RC or 0) are copy constrainted from the previous state,
4. $rotc_i$ is the 1 left rotation of the value represented in $cl_i$. This is handled by the `q_rotation` constraint of the [decomposition subconfig](decomposition_subconfig.md).

We then present the $\theta$ step after having done the above and therefore having the values $cl_i$, $rotc_i$.

|         selectors                             | offset | dc         |  adv0     |  adv1   |  acc    |   limbs   |
|-----------------------------------------------|--------|------------|-----------|---------|---------|-----------|
|  `q_spread, q_dc, q_bootstrap`                |   20   |  ah[0,0]   |    X      |    X    | ah[0,0] |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_theta`       |   21   |  am[0,0]   | aold[0,0] |   c_4   | acc00_1 |    ...    |
|  `q_spread, q_dc, q_rotation`                 |   22   |  al[0,0]   |  rotc_1   |   RC    | acc00_2 |    ...    |
|                                               |   23   |  rota[0,0] |    X      |    X    |  X      |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_theta`       |   24   |  am[0,1]   | aold[0,1] |   c_4   | am[0,1] |    ...    |
|  `q_spread, q_dc, q_rotation`                 |   25   |  al[0,1]   |  rotc_1   |    0    | acc01_1 |    ...    |
|                                               |   26   |  rota[0,1] |    X      |    X    |  X      |    ...    |
|                                               |        |   .        |    .      |    .    |  .      |     .     |
|                                               |        |   .        |    .      |    .    |  .      |     .     |
|                                               |        |   .        |    .      |    .    |  .      |     .     |
|  `q_spread, q_dc, q_bootstrap, q_theta`       |   93   |  am[4,4]   | aold[4,4] |   c_3   | am[4,4] |    ...    |
|  `q_spread, q_dc, q_rotation`                 |   94   |  al[4,4]   |  rotc_0   |    0    | acc44_1 |    ...    |
|                                               |   95   |  rota[4,4] |    X      |    X    |  X      |    ...    |

In the above, the following constraints are applied:

1. $al_{i,j}$ is bootstrapped value of $accij_1$ ($acc00_2$ for the case of $a_{0,0}$ which needs three rows to be bootstrapped). This is handled by the `q_bootstrap` constraint of the [bootstrap subconfig](bootstrap_subconfig.md)  and the `q_spread`, `q_dc` selectors of the [decomposition subconfig](decomposition_subconfig.md)
2. All values of the $adv_0, adv_1$ columns must be copy constrainted from the corresponding previously computed values or by constants.
3. The value $accij_1$ ($acc00_2$ for the case $a_{0,0}$) must be equal to $aold_{i,j} + c_{i-1}  rotc_{i+1} + r$ where $r$ is either the round constant or zero. This is handled by the `q_theta` selector of the [auxiliary linear combination subconfig](aux_lc_subconfig.md) subconfig.
4. $rota_{i,j}$ must be the rotation of $al_{i,j}$, where the rotation is defined by $i,j$ (see [here](./keccakf.md) for the concrete rotations). This is handled by the `q_rotation` constraint of the [decomposition subconfig](decomposition_subconfig.md).

## The $\rho$ and $\pi$ steps

[Recall](./keccakf.md) that the $\rho$ step is rotating the lanes by appropriate values. We have computed already these rotations at the $\theta$ step. The $\pi$ step permutes the lanes. This adds no constrains on the circuit since we have an array of assigned cells for each lane which we can also permute. 

## The $\chi$ step

Recall that to compute the $\chi$ step, given a state $A_{i,j}$ for $i,j\in\{0,..,4\}$ we need to do the following: 

$$A[i, j] = B[i,j] \oplus (\lnot B[i+1, j] \land B[i+2, j])$$

In this step we also also (optionally) absorb a message lane for the next permutation $M$, which is done by XORing, so the computation becomes

$$A[i, j] = B[i,j] \oplus (\lnot B[i+1, j] \land B[i+2, j]) \oplus M$$

### The spread arithmetic constraints

We now have both AND, NOT and XOR operations. Let's see how to do them via packed arithmetic. 

First, note that if we have the spread value of 11...1, which is 001_001...001, and we subtract a spread value of a word $x$ that has no errors, we get the spread value of NOT $x$. This operation *introduces no error*.

Furthermore, we know that the XOR operation corresponds to adding on the field, bootstrapping and taking the least significant bits and the AND operation corresponds to adding on the field and taking the middle bits as the result. 

We can now proceed as follows: 

First compute $(\lnot B[i+1, j] \land B[i+2, j])$ via packed arithmetic. This corresponds to doing the operation:

$$ (\textasciitilde ones - \textasciitilde B[i+1, j] + \textasciitilde B[i+2, j]) $$

where $ones$ is the spread form of 11...1. We know that the result is in the middle bits of the sum. Note that since we add two values, there is *no error* on the high bits.

Next, we need to XOR the result with $B[i,j]  \oplus M$. To do this, we first *shift* this value to align with the result of the AND, and add these values with the previous result. Since we shifted, the result of our computation will now be *on the middle bits* instead of the least significant ones. Crucially, since we add 3 values, the error is small and is absorbed by the high bits in full; there is no carry that affects the next bit group. 

Therefore, the computation we need to do on the field is 

$$ \textasciitilde A[i, j] = 2\cdot (\textasciitilde B[i,j] + \textasciitilde M) + (\textasciitilde ones - \textasciitilde B[i+1, j] + \textasciitilde B[i+2, j])  $$

and get the result as the middle bits of the resulting spread word.

### The layout

|         selectors                             | offset | dc_res   |  adv0   |  adv1    |  acc    |   limbs   |
|-----------------------------------------------|--------|----------|---------|----------|---------|-----------|
|  `q_spread, q_dc, q_bootstrap`                |   96   |  ah[0,0] |   X     |    X     | ah[0,0] |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_chi`         |   97   |  am[0,0] |  a[0,0] |   M_0    | acc00_1 |    ...    |
|  `q_spread, q_dc`                             |   98   |  al[0,0] |  a[1,0] |  a[2,0]  | aerr00  |    ...    |
|  `q_spread, q_dc, q_bootstrap`                |   99   |  ah[0,1] |   X     |    X     | ah[0,1] |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_chi`         |  100   |  am[0,1] |  a[0,1] |   M_1    | acc01_1 |    ...    |
|  `q_spread, q_dc`                             |  101   |  al[0,1] |  a[1,1] |  a[2,1]  | aerr01  |    ...    |
|                                               |        |   .      |    .    |    .     |  .      |     .     |
|                                               |        |   .      |    .    |    .     |  .      |     .     |
|                                               |        |   .      |    .    |    .     |  .      |     .     |
|  `q_spread, q_dc, q_bootstrap`                |  168   |  ah[4,4] |   X     |    X     | ah[4,4] |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_chi`         |  169   |  am[4,4] |  a[4,4] |    0     | acc44_1 |    ...    |
|  `q_spread, q_dc`                             |  170   |  al[4,4] |  a[0,4] |  a[1,4]  | aerr44  |    ...    |

In the above, the following constraints are applied:

1. $al_{i,j}$ is the bootstraped value of $aerr_{i,j}$. This is handled by the `q_bootstrap` constraint of the [bootstrap subconfig](bootstrap_subconfig.md)  and the `q_spread`, `q_dc` selectors of the [decomposition subconfig](decomposition_subconfig.md).
2. All values of the $adv_0, adv_1$ columns must be copy constrainted from the corresponding previously computed values or by constants.
3. The value $aerr_{ij}$  must be equal to $2\cdot (a_{i,j} + M_k) + \textasciitilde ones - a_{i+1,j} + \textasciitilde a_{i+2,j}$ where $M_j$ is either the message to be absorbed on this state part (only on the last round and for 17 state elements) or zero. This is handled by the `q_chi` selector of the [auxiliary linear combination subconfig](aux_lc_subconfig.md) subconfig.

## The final $\iota$ step

We generally handle the $\iota$ computation (recall that this corresponds to a single operation $A[0,0]\oplus RC[r]$) at the begining of the next round to save a few rows. But we still need to do that on the very last round. This computation is done as the $\theta$ computation since this is only XORs. We simply need to set some of the added values to zeros. We next present the layout for this step. 

|         selectors                             | offset | dc_res   |  adv0   |  adv1   |  acc    |   limbs   |
|-----------------------------------------------|--------|----------|---------|---------|---------|-----------|
|  `q_spread, q_dc, q_bootstrap`                |  4104  |  am[0,0] | a[0,0]  |  RC[24] | am[0,0] |    ...    |
|  `q_spread, q_dc, q_bootstrap, q_iota`        |  4105  |  al[0,0] |    0    |    0    | acc     |    ...    |

In the above, the following constraints are applied:

1. $al[0,0]$ is the bootstraped value of $acc$. This is handled by the `q_bootstrap` constraint of the [bootstrap subconfig](bootstrap_subconfig.md)  and the `q_spread`, `q_dc` selectors of the [decomposition subconfig](decomposition_subconfig.md).
2. The value $adv_0$ at offset $4104$ must be copy constraint from the current state value $a_{0,0}$, the value $adv_0$ at offset 4104 must be the fixed value RC[24] and the values of both $adv_0, adv_1$ at offset 4105 must be the fixed 0 values.
3. The value $acc$  must be equal to $a[0,0] + RC[24]$. This is handled by the `q_iota=q_theta` selector of the [auxiliary linear combination subconfig](aux_lc_subconfig.md) subconfig.
