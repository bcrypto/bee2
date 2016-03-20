/*!
*******************************************************************************
\file sd.h
\author (С) НИИ ППМИ, Олег Соловей
\date 2010
\version 1.0

Описание алгоритмов работы с двоичными деревьями, используемых при 
широковещательном шифровании в библиотеке bee.

\remark Все вершины в двоичном дереве нумеруются с 1 до 2n-1, где n=2^h, 
h --- высота дерева (длина пути из корня в лист). Нумерация начинается 
с корня и ведется слева направо. При задании дерева хранится информация 
лишь о листьях дерева. Номер вершины будем отождествлять с номером бита 
в массиве. Вершина является листом, если соответствующий бит установлен в 1.
Размер буфера для хранения дерева равен BE_SIZE_TREE(h) байтов (см. ниже).
*******************************************************************************
*/

#if !defined(__BEE2_SD_H)
#define __BEE2_SD_H

#include "bee2/defs.h"
#include "bee2/core/err.h"

///////////////////////////////////////////////////////////////////////////////
// Определение максимальной высоты h бинарного дерева (3<=h<=25)
// (используется при проверке корректности параметров функций).
///////////////////////////////////////////////////////////////////////////////
#ifndef BE_MAX_HEIGHT
#define BE_MAX_HEIGHT 25
#endif

/////////////////////////////////////////////////////////////////////
//    Вспомогательные макросы
////////////////////////////////////////////////////////////////////
// определение размера в байтах буфера для хранения листьев
#define BE_SIZE_LEAVES(h) ((u32) 1 << (h-3))
// определение размера в байтах буфера для хранения дерева
#define BE_SIZE_TREE(h) ((u32) 1 << (h-2))
// количество листьев в двоичном дереве высоты h (т.е. n=2^h)
#define BE_COUNT_LEAF(h) ((u32) (1 << h))
// количество вершин в двоичном дереве высоты h    (т.е. 2n-1)
#define BE_COUNT_VERTEX(h)    ((u32) ((1 << (h + 1))-1))

#ifdef __cplusplus
extern "C" {
#endif

///////////////////////////////////////////////////////////////////////////////
// Определение глубины вершины (т.е. длины пути из корня в данную вершину).
// Возвращаемое значение: 
//        глубина вершины (принимает значения от 0 до 31).
// Замечание:
//        проверка v на ноль в функции не производится.
///////////////////////////////////////////////////////////////////////////////
u8 beGetDepth (
    u32 v    // [ in] номер вершины (может принимать значения от 1 до 2^{32}-1)
);

///////////////////////////////////////////////////////////////////////////////
// Нахождение ближайшего общего предка вершин v_a и v_b.
// Возвращаемое значение: 
//        номер ближайшего общего предка или 0 (если по крайней мере 
//        один из параметров = 0).
///////////////////////////////////////////////////////////////////////////////
u32 beGetAncestor (
    u32 a,    // [ in] номер вершины (может принимать значения от 1 до 2^{32}-1)
    u32 b    // [ in] номер вершины (может принимать значения от 1 до 2^{32}-1)
);

/*****************************************************************************
    Проверка того, что вершина b является потомком вершины a (a <= b).
    Возвращаемое значение:
        TRUE    - b является потомком вершины a;
        FALSE    - в противном случае.
    Примечание:
        проверка корректности параметров не производится.
*****************************************************************************/
bool_t beIsDescendant (
    u32 a,    /* [ in] номер вершины (может принимать значения от 1 до b */
    u32 b    /* [ in] номер вершины (может принимать значения от 1 до 2^{32}-1) */
);

/*****************************************************************************
    Определение весса Хэмминга буфера (количества листьев), а также номеров первого
    и последнего значащих битов в буфере.
    Возвращаемое значение:
        количество ненулевых битов в буфере.
*****************************************************************************/
u32 beGetCountLeaves (
    u8 * pBuff,    /* [ in] указатель на буфер */
    u32  len,    /* [ in] длина буфера в байтах */
    u32 *first,  /* [out] номер первого значащего бита в буфере(нумерация ведется с нуля) */
    u32 *last);  /* [out] номер последнего значащего бита в буфере */

/*****************************************************************************
    Нахождения <<первого>> листа в дереве T высоты h начиная с вершины 
    с номером a и заканчивая вершиной с номером b.
    Возвращаемое значение:
        номер листа (начинается с единицы) или 0, если листа не существует;
*****************************************************************************/
u32 beGetFirstLeave (
    u8 *T,    /* [ in] указатель на двоичное дерево */
    u32 a,    /* [ in] номер листа, с которого начинается поиск */
    u32 b    /* [ in] номер листа, до которого ведется поиск */
);

/*****************************************************************************
    Построение множества листев S_{a,b} (разрешенное множестов) по вершине дерева a, 
    которая не является листом, и вершине b, которая является предком a: 
    множество включает все листья-потомки вершины a, исключая все листья-потомки вершины b. 
    Результатом работы функции является буфер R, размера 2^(h-3) байтов 
    (память под буфер должна быть выделена заранее), в котором каждый бит 
    ассоциируется с листом (бит устанавливается, если лист является 
    разрешенным). Младший бит в буфере соответствует вершине дерева 
    с номером 2^h, а самый старший - (2^(h+1)-1).
    ОСОБЫЙ СЛУЧАЙ: a = b = 0. В этом случае все пользователи являются разрешенными.
    Возвращаемое значение:
        ERR_OK  - успешное завершение.
        ERR_INVALID_PARAMETER - неверно задан параметр. 
    Примечание: 
        1. Размер выходного буфера R определяется высотой дерева и может быть определен 
        с помощью макроса BE_SIZE_LEAVES(h).
        2. Функция устанавливает в единицу лишь биты, соответствующие "разрешенным" 
        листьям. При этом функция не устанавливает в ноль биты, соответствующие
        "запрещенным" листьям (сделано для удобства использования функции).
*****************************************************************************/
err_t beSetLegalLeaves(
    u8  h,  // [ in] высота дерева (не меньше 3 и  не больше BE_MAX_HEIGHT)
    u8 *R,  // [out] множество листьев (размера 2^(h-3) байтов)
    u32 a,  // [ in] номер вершины дерева (от 1 до 2^h-1 и 0 для особого случая)
    u32 b   // [ in] номер вершины дерева, являющейся потомком вершины a
);

/****************************************************************************
    Определение того, принадлежит ли лист "с" множеству S_{a,b}, где S_{a,b} ---
    множество листьев, которые являются предками вершины a и не являются предками
    вершины b.
    ОСОБЫЙ СЛУЧАЙ: a = b = 0 (в этом случае полагается, что S_{0,0} --- это
    множество всех листьев полного бинарного дерева).
    Возвращаемое значение:
        ERR_OK  - успешное завершение.
        ERR_INVALID_PARAMETER - неверно задан параметр. 
*****************************************************************************/
err_t beCheckLeaf(
    u8  h,  // [ in] высота дерева (не меньше 3 и не больше BE_MAX_HEIGHT)
    u32 a,  // [ in] номер вершины дерева (от 1 до 2^h-1 и 0 для особого случая)
    u32 b,  // [ in] номер вершины дерева, являющейся потомком вершины a
    u32 c   // [ in] номер вершины дерева, являющейся листом (от 2^h до 2^{h+1}-1)
);


/****************************************************************************
    Построение множества индексов, определяющих множество-покрытие для 
    заданного множества запрещенных листьев.
    Построение множества производится по множеству запрещенных листев R,
    в котором номер ненулевого бита определяет номер запрещенного листа 
    (самый младший бит - это первый лист).
    Возвращаемое значение:
        ERR_OK  - успешное завершение;
        ERR_INVALID_PARAMETER - неверно задан параметр. 
        ERR_NOT_ENOUGH_MEMORY - ошибка выделения памяти. 
        ERR_INTERNAL - внутренняя ошибка. 
    Примечание: 
        если r == 0, то в r возвращвется количество "запрещенных" листьев
****************************************************************************/
err_t beCreateIdsCover(
    u8 h,    // [ in] высота дерева 
    u32 *r,    // [ in/out] количество запрещенных листев
    u8 *R,    // [ in] множество запрещенных листьев
    u32 *d,    // [out] количество пар индексов/размер массива
    u8 *C    // [out] массив пар индексов
);

#ifdef __cplusplus
}
#endif

#endif //__BEE2_SD_H
