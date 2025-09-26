# The lookup table

The chip utilizes *a single lookup* table to implement all operations. Specifically, the lookup table allows to do the conversion of spread <-> dense to implement [packed arithmetic](techniques.md#packed-arithmetic).

The lookup contains the following values: 

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

Above, the tag denotes a bit length, and the notation ~x denotes the spread form of x. As an example, to convert a 7 bit word x to spread form verifiably, it is enough to lookup the 
tuple (7, x, ~x). With this lookup, we can do the following operations: 

- range check dense bits by looking up (tag, dense)
- range check spread bits by looking up (tag, spread)
- spread <-> dense by looking up (dense, spread)
- rangechecked spread <-> dense by looking up (tag, dense, spread)

Note that because of the tags, values are repeated and therefore the table has size 2^14. This would require a 2^15 circuit, due to some extra rows used for zero knowledge. We overcoming this by not repeating the existing values for tag=13 and instead of looking up (13, dense, spread), we simply lookup (dense, spread), i.e. search in the whole table. We are able to 
do it since the tag column will *always correspond to a fixed column*.
