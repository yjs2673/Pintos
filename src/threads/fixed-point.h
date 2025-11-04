#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* 고정 소수점 */
#define F (1 << 14)

/* 정수를 고정 소수점으로 변환 */
#define INT_TO_FP(n) ((n) * F)

/* 고정 소수점을 정수로 변환 (소수점 이하 버림) */
#define FP_TO_INT_TRUNC(x) ((x) / F)

/* 고정 소수점을 정수로 변환 (반올림) */
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)

/* FP + FP */
#define FP_ADD(x, y) ((x) + (y))

/* FP - FP */
#define FP_SUB(x, y) ((x) - (y))

/* FP + int */
#define FP_ADD_INT(x, n) ((x) + (n) * F)

/* FP - int */
#define FP_SUB_INT(x, n) ((x) - (n) * F)

/* FP * FP */
#define FP_MUL(x, y) (((int64_t)(x)) * (y) / F)

/* FP * int */
#define FP_MUL_INT(x, n) ((x) * (n))

/* FP / FP */
#define FP_DIV(x, y) (((int64_t)(x)) * F / (y))

/* FP / int */
#define FP_DIV_INT(x, n) ((x) / (n))

#endif