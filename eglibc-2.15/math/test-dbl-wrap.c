#include <math.h>
#include <stdio.h>

#define N 4

static int
do_test (int argc, char *argv[])
{
  int i;
  int result = 0;

  const double eps = 0.01, pi = 3.14;
  const double sin_data[N][2]
    = {{0.0, 0.0}, {pi / 6, 0.5}, {pi / 4, 0.707}, {pi / 3, 0.866}};
  const double exp_data[N][2]
    = {{0.0, 1.0}, {0.5, 1.649}, {1.0, 2.718}, {2.718, 15.150}};

  for (i = 0; i < N; ++i)
    {
      double x, y;
      double s1, c1, t1, e1;
      double s2, c2, t2, as2, ac2, at2, e2, l2;

      x = sin_data[i][0];
      s1 = sin_data[i][1];
      c1 = sqrt (1 - s1 * s1);
      t1 = s1 / c1;

      s2 = sin (x);
      c2 = cos (x);
      t2 = tan (x);
      as2 = asin (s1);
      ac2 = acos (c1);
      at2 = atan (t1);

      y = exp_data[i][0];
      e1 = exp_data[i][1];

      e2 = exp (y);
      l2 = log (e1);

      if (fabs (s1 - s2) > eps)
	{
	  result |= 1;
#if PRINT
	  printf ("sin(%.3lf) = %.3lf\n", x, s2);
#endif
	}

      if (fabs (c1 - c2) > eps)
	{
	  result |= 2;
#if PRINT
	  printf ("cos(%.3lf) = %.3lf\n", x, c2);
#endif
	}

      if (fabs (t1 - t2) > eps)
	{
	  result |= 4;
#if PRINT
	  printf ("tan(%.3lf) = %.3lf\n", x, t2);
#endif
	}

      if (fabs (x - as2) > eps)
	{
	  result |= 8;
#if PRINT
	  printf ("asin(%.3lf) = %.3lf\n", s1, as2);
#endif
	}

      if (fabs (x - ac2) > eps)
	{
	  result |= 16;
#if PRINT
	  printf ("acos(%.3lf) = %.3lf\n", c1, ac2);
#endif
	}

      if (fabs (x - at2) > eps)
	{
	  result |= 32;
#if PRINT
	  printf ("atan(%.3lf) = %.3lf\n", t1, at2);
#endif
	}

      if (fabs (e1 - e2) > eps)
	{
	  result |= 64;
#if PRINT
	  printf ("exp(%.3lf) = %.3lf\n", y, e2);
#endif
	}

      if (fabs (y - l2) > eps)
	{
	  result |= 128;
#if PRINT
	  printf ("log(%.3lf) = %.3lf\n", e1, l2);
#endif
	}
    }

  return result;
}

#include "../test-skeleton.c"
