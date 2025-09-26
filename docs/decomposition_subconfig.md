# Decomposition subconfig

This subconfig is tasked to assert that a value corresponds to a spread lane (64 bit word). This is done by 

1. decomposing the word in small limbs (at most 13-bit length) and asserting via a linear combination that this decomposition is correct,
2. the limbs are spread bits of specific length via the [lookup table](lookup.md).

The exact limb sizes depend on the rotation that we will later do on the specific word, but it is always the case that the sum of the limb sizes is 64. For choosing the limb sizes based on the rotation see [here](techniques.md#rotations).

The linear combination is handled by having one fixed column associated with each limb. We then set the appropriate constant value in this column that corresponds to the appropriate limb coefficient. 

The subconfig also allows to compute word rotations. This is simply done by taking a different linear combination of the limbs (recall that we always set the limb sizes appropriately to support a specific rotation so there always exists two sets of coefficients to get the recomposed and rotated word). This rotation is done using the fixed coefficients of the *next* row and the rotated result also goes on the next row.

## Implementing the constraints

The subconfig defines three constraints: lookup constraints and linear combination constraints for the recomposed and rotated word.

A row looks as follows and we also include the next row that defines the rotated word:

| tag_1 | tag_2 | res | limb_1 | ... | limb_6 | c_1  | ... | c_6  |
|-------|-------|-----|--------|-----|--------|------|-----|------|
|  t_1  |  t_2  |  r  |   l_1  | ... |  l_6   | c_1  | ... | c_6  |
|   X   |   X   | rot |    X   | ... |   X    | c_1' | ... | c_6' |

There are 6 lookups for each row. Three full limb lookups, one "leftover" limb lookup and two variable size lookups. Note that always the full limb lookups happen first, followed by 
the leftover limb lookup and finally the two variable size lookups. The order does not matter since we set the appropriate coefficient for each when doing the linear combination.

More concretely, the lookups -enabled by the `q_spread` selector, check that the following values are in the table: 

- $l_i \in T_{spread}$ for $i\in\{1,2,3\}$
- $(12, l_4) \in (T_{tag}, T_{spread})$
- $(t_1, l_5) \in (T_{tag}, T_{spread})$
- $(t_2, l_6) \in (T_{tag}, T_{spread})$

It is always the case that $t_1 + t_2 = 13$ and therefore the sum of the limb sizes is always 64.

The selector `q_dc` adds the constraint $\sum_i c_i(X) \cdot limb_i(X) = res(X)$. Here $c_i$ are set to be the coefficients that define the linear combination of the limbs that yield the word based on the rotation we want to use

The selector `q_rotation` adds the constraint $\sum_i c_i(\omega X) \cdot limb_i(X) = res(\omega X)$. Here $c_i'$ are set to be the coefficients that define the linear combination of the limbs that yield the rotated word.

No check is needed for the values of $c_i, c_i'$ since they are fixed and part of the circuit.

Note that the second row above is only used when we actually need to compute the rotation of a word, see [keccak operations subconfig](keecak_operations_subconfig.md) for details.
