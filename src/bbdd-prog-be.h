#define BBDD_UINT16_T __u16
#define BBDD_UINT32_T __u32
#define BBDD_UINT64_T __u64

#define BBDD_HTOBE16 bpf_htons
#define BBDD_HTOBE32 bpf_htonl
#define BBDD_HTOBE64 bpf_cpu_to_be64

#define BBDD_BE16TOH bpf_ntohs
#define BBDD_BE32TOH bpf_ntohl
#define BBDD_BE64TOH bpf_be64_to_cpu

# include "bbdd-be.t"

#undef BBDD_BE64TOH
#undef BBDD_BE32TOH
#undef BBDD_BE16TOH

#undef BBDD_HTOBE64
#undef BBDD_HTOBE32
#undef BBDD_HTOBE16

#undef BBDD_UINT64_T
#undef BBDD_UINT32_T
#undef BBDD_UINT16_T
