#include "taints_merge_list.h"
#include <stdio.h>

void test2()
{
    struct taint t;
    struct taint t2;
    struct taint t3;
    struct taint t4;
    struct taint t5;
    struct taint t6;
    
    new_taint(&t);
    new_taint(&t2);
    new_taint(&t3);
    new_taint(&t4);
    new_taint(&t5);
    new_taint(&t6);

    set_taint_value(&t, 1, 1);
    set_taint_value(&t2, 2, 1);
    set_taint_value(&t3, 3, 1);
    set_taint_value(&t4, 4, 1);
    
    set_taint(&t5, &t);
    assert(get_taint_value(&t5, 1));

    merge_taints(&t5, &t4);
    assert(get_taint_value(&t5, 1));
    assert(get_taint_value(&t5, 4));

    merge_taints(&t6, &t2);
    assert(get_taint_value(&t6, 1));
    assert(get_taint_value(&t6, 2));
    assert(get_taint_value(&t6, 4));
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

    fprintf(stdout, "done\n");

    return 0;
}

