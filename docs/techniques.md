# Techniques overview

## Packed Arithmetic

We can view a u64 number $c$ as a sequence of (little endian) bits $b_0 b_1 \ldots b_{63}$. These are connected via the equation $c = \sum_i b_i 2^i$

Packed arithmetic consists of changing the base 2 in the above with a larger basis (we will use 8). This means that we now represent the original $c$ as $\textasciitilde c = \sum_i b_i 8^i$.

and writing this number in binary form coresponds to $00b_0 00b_1 \ldots 00b_{63}$. This defines the mapping $spread(c) = \textasciitilde c$ and $dense(\textasciitilde c) = c$. Note that the latter is only defined when $dense(\textasciitilde c)$ is of the above form (each "limb" is a zero/one value).

This allows us to do (limited) bitwise operations because the extra zeros will "absorb" any carry terms and won't affect any other terms. As an example consider the xor function. When we add three values $00b + 00c + 00d$ where $b, c, d$ are zero or one, the result will be $0\ X\ (b \oplus c \oplus d)$, that is: 

- the rightmost bit will hold the xor result,
- the middle bit will be either 0 or 1,
- the leftmost bit will be 0.

Similarly, when adding up to 7 numbers, the result will be $X X (b_1 \oplus \ldots \oplus b_7)$. Note that in this case the rightmost bit will not be necessarily zero. If we try to add more numbers we no longer end up with the xor result, since the *accumulated error* (i.e. the carries) is too big and might introduce a "fourth bit". When doing bitwise operations, this fourth bit will affect the next terms.

Similarly, it is easy to see that 

- $001 - 00b = 0\ 0\ \lnot b$
- $00b + 00c = 0\ (b \land c)\ (b \oplus c)$

This extends naturally to bitwise operations: as long as we do not do a lot of operations, the "accumulated error" will not affect the rest of the bits. 

## Bootstrapping

We call *bootstrapping* the process that takes a spread number *with errors* (i.e. it is the result of some operations) and removes the error. A spread number that possibly holds errors can be written as three spread numbers $(\textasciitilde c_L, \textasciitilde c_M, \textasciitilde c_H)$ that are "errorless" and representing the leftmost, middle and rightmost bits. 

The relation that is satisfied is  $\textasciitilde c = 4 \textasciitilde c_L + 2 \textasciitilde c_M + \textasciitilde c_H$

If this equation is satisfied and the the three values are indeed "errorless" spread forms, we can take any of them (depending on what operation we did) as the new bootstrapped spread form.

## Decompositions 

There is no efficient native operation that can compute the spread -> dense or dense -> spread function on the native field of the snark. Therefore, we need to rely on lookups for these computations. 

We can create a table with the function's boolean table:

| Dense          | Spread          |
|----------------|-----------------|
|   0            |   ~0            |
|   1            |   ~1            |
|   2            |   ~2            |
|   3            |   ~3            |
|   .            |    .            |
|   .            |    .            |
|   .            |    .            |
|   .            |    .            |
| 2^64 - 1       |~(2^64 - 1)      |

and rely on lookups for these conversions. This is, however, a huge lookup. We thus rely on a smaller table (concretely supporting values from 0 to $2^{13} - 1$). We also use tags to be able to locate values that should be in the range $[2^r, 2^{r+1})$.

Therefore, our lookup table looks as follows:

| Tag            | Dense          | Spread          |
|----------------|----------------|-----------------|
|   0            |   0            |   ~0            |
|   1            |   0            |   ~0            |
|   1            |   1            |   ~1            |
|   2            |   0            |   ~0            |
|   2            |   1            |   ~1            |
|   2            |   2            |   ~2            |
|   2            |   3            |   ~3            |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   13           |   2^12         |   ~2^12         |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   .            |   .            |    .            |
|   13           | 2^13 - 1       |~(2^13 - 1)      |


**Note:** We do not need all values for the 13 tag. When we search a 13-bit number it is enough to search the whole table, so we simply search without a tag. Therefore, we only add the values that are not already on the table. It is important to have an unused tag in the newly added values (here 13) to prevent them from being used in a smaller size lookup.

To compute a spread -> dense or dense -> spread of a u64, we can convert it to (fixed size) limbs, look them up and take a linear combination. For example, decomposing a number in 8-bit limbs, we can use the constraints:

$$c = c_0 + 2 c_1 + 2^2 c_2 + \ldots + 2^7 c_7$$
$$\sim c = \sim c_0 + 8 \sim c_1 + 8^2 \sim c_2 + \ldots + 8^7 \sim c_7$$
$$ \forall c_i. (8, c_i, \sim c_i)\in T$$

Note that *any limb size combination* with sizes adding up to 64 would work. 

## Rotations 

As part of the keccak-f permutation we need to implement various bit rotations. We do this by taking advantage of the flexibility of doing decompositions with variable limb sizes. Depending on the rotation we want to use, we choose the appropriate limb-sizes, meaning there is a linear combination of the limbs that results in the rotated word. We demonstrate this with examples: 


|        | limb1 | limb2 | limb3 | limb4 | limb5 | limb6 |
|--------|-------|-------|-------|-------|-------|-------|
| rot=1  |  13   |  13   |  13   |  12   |  12   |  1    |
| rot=4  |  13   |  13   |  13   |  12   |   9   |  4    |
| rot=20 |  13   |  13   |  12   |   6   |   7   |  13   |

In the first case, we can simply take the rotated word as:

$$ 
limb_5 + 2^{12} limb_4 + 2^{25} limb_3 + 2^{38} limb_2 + 2^{51} limb_1 + 2^{52} limb_6
$$

in the second:

$$ 
limb_5 + 2^{9} limb_4 + 2^{21} limb_3 + 2^{34} limb_2 + 2^{48} limb_1 + 2^{52} limb_6
$$

and in the third:

$$ 
limb_4 + 2^{6} limb_3 + 2^{18} limb_2 + 2^{31} limb_1 + 2^{44} limb_6 + 2^{57} limb_5
$$

There are more than one ways to find such decompositions. Our approach works by 

- using 3 full size (=13) limb
- two small limbs that add to 13
- a leftover limb of size 12
