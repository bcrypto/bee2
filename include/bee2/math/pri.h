﻿/*
*******************************************************************************
\file pri.h
\brief Primes
\project bee2 [cryptographic library]
\author (С) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\created 2012.08.13
\version 2014.07.18
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file pri.h
\brief Простые числа
*******************************************************************************
*/

#ifndef __PRI_H
#define __PRI_H

#include "bee2/math/zz.h"

#ifdef __cplusplus
extern "C" {
#endif

/*!
*******************************************************************************
\file pri.h

Реализована проверка простоты натуральных чисел и построение больших простых.
Числа представляются по правилам zz.h.

Используется факторная база, составленная из малых простых.

\pre Все входные указатели действительны.

\pre Вспомогательный буфер stack не пересекается с другими буферами.

\safe todo
*******************************************************************************
*/

/*
*******************************************************************************
Факторная база
*******************************************************************************
*/

/*!	\brief Размер факторной базы

	Возвращается число элементов факторной базы, т.е. число поддерживаемых
	первых нечетных простых.
	\pre Максимальный элемент факторной базы укладывается в половину машинного 
	слова.
	\return Размер факторной базы.
*/
size_t priBaseSize();

/*!	\brief Простое из факторной базы

	Определяется i-й элемент факторной базы, т.е. (i + 1)-ое нечетное 
	простое число.
	\pre i < priBaseSize().
	\return Элемент факторной базы.
*/
word priBasePrime(
	size_t i			/*!< [in] номер */
);

/*!	\brief Остатки от деления на простые из факторной базы

	Определяются остатки [count]mods от деления числа [n]a на первые count 
	простых из факторной базы.
	\pre count <= priBaseSize().
*/
void priBaseMod(
	word mods[],		/*!< [out] остатки */
	const word a[],		/*!< [in] число */
	size_t n,			/*!< [in] длина a в машинных словах */
	size_t count		/*!< [in] число остатков */
);

/*
*******************************************************************************
Использование факторной базы
*******************************************************************************
*/

/*!	\brief Просеянное?

	Проверяется что число [n]a является нечетным и не делится на base_count 
	первых простых из факторной базы.
	\pre base_count <= priBaseSize().
	\return Признак успеха.
	\remark Число a не считается просеянным, если совпадает с элементом 
	факторной базы. Число a = 1 считается просеянным. 
	\deep{stack} priIsSieved_deep(n).
*/
bool_t priIsSieved(
	const word a[],		/*!< [in] проверяемое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	size_t base_count,	/*!< [in] число элементов факторной базы */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priIsSieved_deep(size_t base_count);

/*!	\brief Гладкое?

	Проверяется что число [n]a делится только на 2 и на base_count 
	первых простых из факторной базы.
	\pre base_count <= priBaseSize().
	\return Признак успеха.
	\remark Число a не считается просеяным, если совпадает с элементом 
	факторной базы. Число a = 1 считается просеянным. 
	\deep{stack} priIsSieved_deep(n).
*/
bool_t priIsSmooth(
	const word a[],		/*!< [in] проверяемое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	size_t base_count,	/*!< [in] число элементов факторной базы */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priIsSmooth_deep(size_t n);

/*
*******************************************************************************
Проверка простоты
*******************************************************************************
*/

/*!	\brief Простое машинное слово?

	Проверяется что число a, которое укладывается в машинное слово, является 
	простым.
	\return Признак простоты.
	\remark Реализован детерминированный тест (без ошибок).
	\deep{stack} priIsPrimeW_deep().
*/
bool_t priIsPrimeW(
	register word a,	/*!< [in] проверяемое число */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priIsPrimeW_deep();

/*!	\brief Тест Рабина -- Миллера

	С помощью теста Рабина -- Миллера проверяется, что число [n]a
	является простым. Выполняется iter итераций теста. 
	\return Признак простоты.
	\remark Тест является вероятностным и возможны ошибки. Вероятность 
	признания простым составного числа не превосходит 1 / 4^iter.
	Простое может быть признано составным, если за большое число попыток 
	не удается построить случайное число из множества {1, 2,.., a - 1}.
	Вероятность последнего события не превосходит 1 / 2^B_PER_IMPOSSIBLE.
	\remark При iter == 0 простым будет признано всякое нечетное число,
	большее 7.
	\deep{stack} priRMTest_deep(n).
*/
bool_t priRMTest(
	const word a[],		/*!< [in] проверяемое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	size_t iter,		/*!< [in] число итераций */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priRMTest_deep(size_t n);

/*!	\brief Простое?

	Проверяется, что число [n]a является простым. Используется
	тест Рабина -- Миллера с числом итераций B_PER_IMPOSSIBLE / 2.
	\return Признак простоты.
	\remark Вероятность ошибки не превосходит 1 / 2^B_PER_IMPOSSIBLE.
	\deep{stack} priIsPrime_deep(n).
*/
bool_t priIsPrime(
	const word a[],		/*!< [in] проверяемое число */
	size_t n,			/*!< [in] длина a в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priIsPrime_deep(size_t n);

/*!	\brief Простое Софи Жермен?

	Проверяется, что нечетное простое число [n]q является простым Софи Жермен, 
	т.е. что 2q + 1 также простое.
	\pre q -- нечетное && q > 1.
	\expect q -- простое.
	\return Признак успеха.
	\remark Реализован детерминированный тест (без ошибок).
	\deep{stack} priIsSGPrime_deep(n).
*/
bool_t priIsSGPrime(
	const word q[],		/*!< [in] проверяемое простое число */
	size_t n,			/*!< [in] длина q в машинных словах */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priIsSGPrime_deep(size_t n);

/*
*******************************************************************************
Генерация простых
*******************************************************************************
*/

/*!	\brief Следующее малое простое

	Определяется минимальное нечетное простое p из интервала [a, 2^l),
	где l -- битовая длина a.
	\return Признак успеха.
*/
bool_t priNextPrimeW(
	word p[1],			/*!< [out] простое число */
	word a,				/*!< [in] начальное значение */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priNextPrimeW_deep();

/*!	\brief Следующее простое

	Определяется минимальное нечетное простое [n]p из интервала [[n]a, 2^l), 
	где l -- битовая длина a. Проверяются на простоту trials первых 
	чисел-кандидатов (или все возможные кандидаты при trials == SIZE_MAX). 
	Сначала проверяется, что кандидат не делится на base_count простых из 
	факторной базы. Затем применяется тест Рабина -- Миллера с iter итерациями.
	\pre Буфер p либо не пересекается с буфером a, либо указатели a и p
	совпадают.
	\pre base_count <= priBaseSize().
	\return TRUE, если искомое простое найдено, и FALSE в противном случае.
	\deep{stack} priNextPrime_deep(n, base_count).
*/

bool_t priNextPrime(
	word p[],			/*!< [out] простое число */
	const word a[],		/*!< [in] начальное значение */
	size_t n,			/*!< [in] длина a и p в машинных словах */
	size_t trials,		/*!< [in] число кандидатов */
	size_t base_count,	/*!< [in] число элементов факторной базы */
	size_t iter,		/*!< [in] число итераций теста Рабина -- Миллера */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priNextPrime_deep(size_t n, size_t base_count);

/*!	\brief Расширение простого

	По базовому нечетному простому [n]q определяется расширенное 
	простое [W_OF_B(l)]p битовой длины l, которое имеет вид 2 * q  * r + 1.
	Число r выбирается с помощью генератора rng с состоянием rng_state.
	Простота построенного числа p проверяется в два этапа. Сначала
	проверяется, что p не делится на base_count простых из факторной
	базы. Затем проверяется условие теоремы Демитко. Если число p не подходит,
	то оно увеличивается на 2 и проверка повторяется. Если при увеличении p
	его битовая длина становится больше l, то генерируется новое r, 
	затем p пересчитывается. Всего используется не более trials кандидатов p.
	При trials == SIZE_MAX ограничений на число кандидатов нет.
	\pre Буфер p не пересекается с буфером q.
	\pre q -- нечетное && q >= 3.
	\pre wwBitSize(q, n) + 1 <= l && l <= 2 * wwBitSize(q, n).
	\pre base_count <= priBaseSize().
	\expect q -- простое.
	\return TRUE, если искомое простое найдено, и FALSE в противном случае.
	\remark При trials == SIZE_MAX проверяются все возможные кандидаты.
	\remark Для применения теоремы Демитко требуется выполнение условия 
	2 * r < 4 * q + 1. Ограничение l <= 2 * wwBitSize(q, n) гарантирует
	выполнение этого условия.
	\deep{stack} priExtendPrime_deep(l, n, base_count).
*/

bool_t priExtendPrime(
	word p[],			/*!< [out] расширенное простое число */
	size_t l,			/*!< [in] длина p в битах */
	const word q[],		/*!< [in] базовое простое число */
	size_t n,			/*!< [in] длина q в машинных словах */
	size_t trials,		/*!< [in] число кандидатов */
	size_t base_count,	/*!< [in] число элементов факторной базы */
	gen_i rng,			/*!< [in] генератор случайных чисел */
	void* rng_state,	/*!< [in] состояние rng */
	void* stack			/*!< [in] вспомогательная память */
);

size_t priExtendPrime_deep(size_t l, size_t n, size_t base_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __PRI_H */
