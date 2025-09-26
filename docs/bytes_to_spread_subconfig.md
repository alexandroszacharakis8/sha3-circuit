# Bytes to Spread Subconfig

The goal of the subconfig is to convert 8 byte arrays to spread lanes and back. Specifically it converts between: $[b_0\ldots b_7]$ <-> spread($b_7b_6...b_0$), where 
$b_7b_6...b_0$ is the concatenation of the bits. 

The subconfig uses three parallel lookups. Roughly, it works as follows: 

1. assert the values $b_7\ldots b_4$ are bytes (rangecheck)
2. spread these values to get $\textasciitilde b_7 \ldots \textasciitilde b_4$
3. take a linear combination of the spread values `hi` corresponding to the recomposed high bits (in spread form) 
1. assert the values $b_3\ldots b_0$ are bytes (rangecheck)
2. spread these values to get $\textasciitilde b_3 \ldots \textasciitilde b_0$
6. take a linear combination of the spread values `lo` corresponding to the recomposed low bits (in spread form) 
7. add the `hi` and `lo` to take the spread word

## The constraints

The subconfig uses two constraints: a lookup constraint and a linear combination constraint. 

The constraint (handled with the selector `q_bytes_to_lane`) are applied to a layout looking as follows (X denotes unused cells): 

|recomposition | intermediate |   l0   | ... |   l3   |
|--------------|--------------|--------|-----|--------|
|      X       |       X      |   a3   | ... |   a0   |
|     ~r       |     prev     |  ~a3   | ... |  ~a0   |

and applies the constraints: 
- $(8, a_i, \textasciitilde a_i)\in T$ corresponding to (1) ai are bytes and (2) $\textasciitilde a_i$ their spread form,
- $\textasciitilde r = 8^{32} prev + 8^{24} a_3 + 8^{16} a_2 + 8^8 a_1 + a_0$ corresponding to correct limb recomposition.
  

## The layout

The circuit layout for the conversion looks as follows (X denotes an unused value): 

|offset| recomposition | intermediate |   l0   | ... |   l3   |
|------|---------------|--------------|--------|-----|--------|
|   0  |      X        |       X      |   b7   | ... |   b4   |
|   1  |     ~r1       |       0      |  ~b7   | ... |  ~b4   |
|   2  |      X        |       X      |   b3   | ... |   b0   |
|   3  |     ~r2       |     ~r1      |  ~b3   | ... |  ~b0   |

The following constraints are applied:
1. $(8, a_i, \textasciitilde b_i)\in T$ (`q_bytes_to_lane` at offsets 0, 2)
2. intermediate at offset 1 is 0
3. intermediate at offset 3 = recomposition at offset 1
4. $8^{32} \cdot 0 + 8^{24} b_7 + 8^{16} b_6 + 8^8 b_5 + 8^0 b_4 = \textasciitilde r_1$ (`q_bytes_to_lane` at offset 0)
5. $2^{32} \textasciitilde r_1 + 8^{24} b_3 + 8^{16} b_2 + 8^8 b_1 + 8^0 b_0 = \textasciitilde r_2$ (`q_bytes_to_lane` at offset 2)

The prover assignes all this values and either copy constraints the values $b_7, \ldots, b_0$ for dense -> spread or $\textasciitilde r_2$ for spread -> dense. This is done by the chip interface.
