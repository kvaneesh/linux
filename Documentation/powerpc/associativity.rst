============================
NUMA resource associativity
=============================

Associativity represents the groupings of the various platform resources into
domains of substantially similar mean performance relative to resources outside
of that domain. Resources subsets of a given domain that exhibit better
performance relative to each other than relative to other resources subsets
are represented as being members of a sub-grouping domain. This performance
characteristic is presented in terms of NUMA node distance within the Linux kernel.
From the platform view, these groups are also referred to as domains.

PAPR interface currently supports different ways of communicating these resource
grouping details to the OS. These are referred to as Form 0, Form 1 and Form2
associativity grouping. Form 0 is the older format and is now considered deprecated.

Hypervisor indicates the type/form of associativity used via "ibm,arcitecture-vec-5 property".
Bit 0 of byte 5 in the "ibm,architecture-vec-5" property indicates usage of Form 0 or Form 1.
A value of 1 indicates the usage of Form 1 associativity. For Form 2 associativity
bit 2 of byte 5 in the "ibm,architecture-vec-5" property is used.

Form 0
-----
Form 0 associativity supports only two NUMA distance (LOCAL and REMOTE).

Form 1
-----
With Form 1 a combination of ibm,associativity-reference-points and ibm,associativity
device tree properties are used to determine the NUMA distance between resource groups/domains.

The “ibm,associativity” property contains one or more lists of numbers (domainID)
representing the resource’s platform grouping domains.

The “ibm,associativity-reference-points” property contains one or more list of numbers
(domainID index) that represents the 1 based ordinal in the associativity lists.
The list of domainID index represnets increasing hierachy of resource grouping. 

ex:
{ primary domainID index, secondary domainID index, tertiary domainID index.. }

Linux kernel uses the domainID at the primary domainID index as the NUMA node id.
Linux kernel computes NUMA distance between two domains by recursively comparing
if they belong to the same higher-level domains. For mismatch at every higher
level of the resource group, the kernel doubles the NUMA distance between the
comparing domains.

Form 2
-------
Form 2 associativity format adds separate device tree properties representing NUMA node distance
thereby making the node distance computation flexible. Form 2 also allows flexible primary
domain numbering. With numa distance computation now detached from the index value of
"ibm,associativity" property, Form 2 allows a large number of primary domain ids at the
same domainID index representing resource groups of different performance/latency characteristics.

Hypervisor indicates the usage of FORM2 associativity using bit 2 of byte 5 in the
"ibm,architecture-vec-5" property.

"ibm,numa-lookup-index-table" property contains one or more list numbers representing
the domainIDs present in the system. The offset of the domainID in this property is considered
the domainID index.

prop-encoded-array: The number N of the domainIDs encoded as with encode-int, followed by
N domainID encoded as with encode-int

For ex:
ibm,numa-lookup-index-table =  {4, 0, 8, 250, 252}, domainID index for domainID 8 is 1.

"ibm,numa-distance-table" property contains one or more list of numbers representing the NUMA
distance between resource groups/domains present in the system.

prop-encoded-array: The number N of the distance values encoded as with encode-int, followed by
N distance values encoded as with encode-bytes. The max distance value we could encode is 255.

For ex:
ibm,numa-lookup-index-table =  {3, 0, 8, 40}
ibm,numa-distance-table     =  {9, 10, 20, 80, 20, 10, 160, 80, 160, 10}

  | 0    8   40
--|------------
  |
0 | 10   20  80
  |
8 | 20   10  160
  |
40| 80   160  10


"ibm,associativity" property for resources in node 0, 8 and 40

{ 3, 6, 7, 0 }
{ 3, 6, 9, 8 }
{ 3, 6, 7, 40}

With "ibm,associativity-reference-points"  { 0x3 }

Each resource (drcIndex) now also supports additional optional device tree properties.
These properties are marked optional because the platform can choose not to export
them and provide the system topology details using the earlier defined device tree
properties alone. The optional device tree properties are used when adding new resources
(DLPAR) and when the platform didn't provide the topology details of the domain which
contains the newly added resource during boot.

"ibm,numa-lookup-index" property contains a number representing the domainID index to be used
when building the NUMA distance of the numa node to which this resource belongs. This can
be looked at as the index at which this new domainID would have appeared in
"ibm,numa-lookup-index-table" if the domain was present during boot. The domainID
of the new resource can be obtained from the existing "ibm,associativity" property. This
can be used to build distance information of a newly onlined NUMA node via DLPAR operation.
The value is 1 based array index value.

prop-encoded-array: An integer encoded as with encode-int specifying the domainID index

"ibm,numa-distance" property contains one or more list of numbers presenting the NUMA distance
from this resource domain to other resources.

prop-encoded-array: The number N of the distance values encoded as with encode-int, followed by
N distance values encoded as with encode-bytes. The max distance value we could encode is 255.

For ex:
ibm,associativity     = { 4, 5, 10, 50}
ibm,numa-lookup-index = { 4 }
ibm,numa-distance   =  {8, 160, 255, 80, 10, 160, 255, 80, 10}

resulting in a new toplogy as below.
  | 0    8   40   50
--|------------------
  |
0 | 10   20  80   160
  |
8 | 20   10  160  255
  |
40| 80   160  10  80
  |
50| 160  255  80  10

