#include "taints_graph.h"
#include <stdio.h>

void create_taints(int num, struct taint** taints)
{
    int i = 0;
    srand(1);
    // assumes taints is allocated already
    for (i = 0; i < num; i++) {
        struct taint* t;
        new_taint(taints[i]);
        set_taint_value(taints[i], rand(), 1);
    }
}

int main(int argc, char** argv)
{
    struct taint t;
    struct taint t2;
    struct taint t3;
    struct taint t4;
    int t_value = 0;

    fprintf(stdout, "Starting taints test\n");
    
    INIT_TAINT_INDEX();

    fprintf(stderr, "make new taint\n");
    new_taint(&t);
    new_taint(&t2);
    new_taint(&t3);
    new_taint(&t4);
    fprintf(stderr, "set taint value\n");
    set_taint_value(&t, 1, 1);
    set_taint_value(&t2, 2, 1);
    set_taint_value(&t3, 3, 1);
    set_taint_value(&t4, 4, 1);
    fprintf(stderr, "get taint value\n");
    t_value = get_taint_value(&t, 1);
    fprintf(stderr, "%d\n", t_value);
    assert (t_value == 1);
    t_value = get_taint_value(&t2, 1);
    assert (t_value == 0);
    t_value = get_taint_value(&t2, 2);
    assert (t_value == 1);

    fprintf(stderr, "merge taints\n");
    merge_taints(&t, &t2);
    t_value = get_taint_value(&t, 2);
    fprintf(stderr, "%d\n", t_value);
    assert (t_value == 1);

    merge_taints(&t3, &t4);
    merge_taints(&t, &t3);

    print_taint(stderr, &t);
    assert(get_taint_value(&t, 1));
    assert(get_taint_value(&t, 2));
    assert(get_taint_value(&t, 3));
    assert(get_taint_value(&t, 4));

    fprintf(stdout, "done\n");

    return 0;
}
