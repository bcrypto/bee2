/*
*******************************************************************************
\file bash.h
\brief STB 34.101.77 (bash): hashing algorithms
\project bee2 [cryptographic library]
\author (C) Sergey Agievich [agievich@{bsu.by|gmail.com}]
\author (C) Vlad Semenov [semenov.vlad.by@gmail.com]
\created 2014.07.15
\version 2016.04.23
\license This program is released under the GNU General Public License 
version 3. See Copyright Notices in bee2/info.h.
*******************************************************************************
*/

#ifndef __BEE2_BASH_AVX2_H
#define __BEE2_BASH_AVX2_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bee2/defs.h"

/*!	\brief Шаговая функция

	Буфер block преобразуется с помощью шаговой функции bashavx2_-f.
	\pre Буфер block корректен.
*/
void bashavx2_F(
	octet block[192]	/*!< [in/out] прообраз/образ */
);

/*
*******************************************************************************
bashavx2_
*******************************************************************************
*/

/*!	\brief Длина состояния

	Возвращается длина состояния (в октетах) алгоритмов хэширования bashavx2_.
	\return Длина состояния.
*/
size_t bashavx2_keep();

/*!	\brief Инициализация

	В state формируются структуры данных, необходимые для хэширования 
	с помощью алгоритмов bashavx2_ уровня l.
	\pre l > 0 && l % 16 == 0 && l <= 256.
	\pre По адресу state зарезервировано bashavx2_keep() октетов.
*/
void bashavx2_Start(
	void* state,		/*!< [out] состояние */
	size_t l			/*!< [in] уровень стойкости */
);	

/*!	\brief Хэширование фрагмента данных

	Текущее хэш-значение, размещенное в state, пересчитывается по алгоритму 
	bashavx2_ с учетом нового фрагмента данных [count]buf.
	\expect bashavx2_Start() < bashavx2_StepH()*.
*/
void bashavx2_StepH(
	const void* buf,	/*!< [in] данные */
	size_t count,		/*!< [in] число октетов данных */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Определение хэш-значения

	Определяются первые октеты [hash_len]hash окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashavx2_StepH().
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashavx2_Start().
	\expect (bashavx2_StepH()* < bashavx2_StepG())*. 
	\remark Если продолжение хэширования не предполагается, то буферы 
	hash и state могут пересекаться.
*/
void bashavx2_StepG(
	octet hash[],		/*!< [out] хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Проверка хэш-значения

	Прооверяется, что первые октеты окончательного хэш-значения 
	всех данных, обработанных до этого функцией bashavx2_StepH(),
	совпадают с [hash_len]hash.
	\pre hash_len <= l / 4, где l -- уровень стойкости, ранее переданный 
	в bashavx2_Start().
	\expect (bashavx2_StepH()* < bashavx2_StepV())*.
	\return Признак успеха.
*/
bool_t bashavx2_StepV(
	const octet hash[],	/*!< [in] контрольное хэш-значение */
	size_t hash_len,	/*!< [in] длина hash */
	void* state			/*!< [in/out] состояние */
);

/*!	\brief Хэширование

	С помощью алгоритма bashavx2_ уровня стойкости l определяется хэш-значение 
	[l / 4]hash буфера [count]src.
	\expect{ERR_BAD_PARAM} l > 0 && l % 16 == 0 && l <= 256.
	\expect{ERR_BAD_INPUT} Буферы hash, src корректны.
	\return ERR_OK, если хэширование завершено успешно, и код ошибки
	в противном случае.
	\remark Буферы могут пересекаться.
*/
err_t bashavx2_Hash(
	octet hash[],		/*!< [out] хэш-значение */
	size_t l,			/*!< [out] уровень стойкости */
	const void* src,	/*!< [in] данные */
	size_t count		/*!< [in] число октетов данных */
);

/*
*******************************************************************************
bashavx2_256
*******************************************************************************
*/

#define bashavx2_256_keep bashavx2_keep
#define bashavx2_256Start(state) bashavx2_Start(state, 128)
#define bashavx2_256StepH(buf, count, state) bashavx2_StepH(buf, count, state)
#define bashavx2_256StepG(hash, state) bashavx2_StepG(hash, 32, state)
#define bashavx2_256StepG2(hash, hash_len, state) bashavx2_StepG(hash, hash_len, state)
#define bashavx2_256StepV(hash, state) bashavx2_StepV(hash, 32, state)
#define bashavx2_256StepV2(hash, hash_len, state) bashavx2_StepV2(hash, hash_len, state)
#define bashavx2_256Hash(hash, src, count) bashavx2_Hash(hash, 128, src, count)

/*
*******************************************************************************
bashavx2_384
*******************************************************************************
*/

#define bashavx2_384_keep bashavx2_keep
#define bashavx2_384Start(state) bashavx2_Start(state, 192)
#define bashavx2_384StepH(buf, count, state) bashavx2_StepH(buf, count, state)
#define bashavx2_384StepG(hash, state) bashavx2_StepG(hash, 48, state)
#define bashavx2_384StepG2(hash, hash_len, state) bashavx2_StepG(hash, hash_len, state)
#define bashavx2_384StepV(hash, state) bashavx2_StepV(hash, 48, state)
#define bashavx2_384StepV2(hash, hash_len, state) bashavx2_StepV2(hash, hash_len, state)
#define bashavx2_384Hash(hash, src, count) bashavx2_Hash(hash, 192, src, count)

/*
*******************************************************************************
bashavx2_512
*******************************************************************************
*/

#define bashavx2_512_keep bashavx2_keep
#define bashavx2_512Start(state) bashavx2_Start(state, 256)
#define bashavx2_512StepH(buf, count, state) bashavx2_StepH(buf, count, state)
#define bashavx2_512StepG(hash, state) bashavx2_StepG(hash, 64, state)
#define bashavx2_512StepG2(hash, hash_len, state) bashavx2_StepG(hash, hash_len, state)
#define bashavx2_512StepV(hash, state) bashavx2_StepV(hash, 64, state)
#define bashavx2_512StepV2(hash, hash_len, state) bashavx2_StepV2(hash, hash_len, state)
#define bashavx2_512Hash(hash, src, count) bashavx2_Hash(hash, 256, src, count)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2_BASH_H */
