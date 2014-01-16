#ifndef TAINTS_ARRAY_H
#define TAINTS_ARRAY_H

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_OPTIONS 1000

struct taint {
	TAINT_TYPE options[NUM_OPTIONS];
};

#ifdef __cplusplus
}
#endif

#endif // end guard TAINTS_ARRAY_H
