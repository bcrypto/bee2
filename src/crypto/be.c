/*****************************************************************************
 Notices:    Copyright (c) 2010 APMI
 Author:    Соловей Олег
*****************************************************************************/

/******************************************************************************
 Данный модуль реализует алгоритмы широковещательного шифрования в соответствии
 со спецификацией протокола широковещательного шифрования.
 ******************************************************************************/

#include "bee2/crypto/be.h"
#include "bee2/crypto/belt.h"
#include "bee2/core/mem.h"
#include "bee2/math/sd.h"

#define BE_SIZE_IMITO 8
#define BE_SIZE_SYNHRO 16

/*    Массив для быстрого поиска ключей в массиве всех ключей
    Строится по правилу: 
    for (h=3; h<26; h++) // h=25 - максимальное значение
    {
        beOffsetAKey[h-3][0] = 1;
        for (i=0; i<h; i++)
        {    
            beOffsetAKey[h-3][i+1]=beOffsetAKey[h-3][i]+(1<<i)*((1<<(h-i+1))-2);
        }        
    }
    Поясним алгоритм построения для h=3 (соответствует первой строке массива beOffsetAKey).
    Первый элемент в строке (beOffsetAKey[0][0]) --- это количество ключей, которые сообтветствует 
    случаю, когда все пользователи разрешены.
    Второй элемент это сумма первого элемена и количества ключей С_{1,i}, где i пробегает 
    все потомков вершины 1 для полного двоичного дерева высоты h=3.
    Третий элемент это сумма второго элемента и количества ключй С_{2,i} и С_{3,j} 
    (вершины 2 и 3 находятся на одном уровне), где i пробегает все потомков вершины 2, 
    а j --- всех потомков вершины 3 для полного двоичного дерева высоты h=3.
    Четвертый элемент сумма третьего элемента и количества ключй С_{4,i}, С_{5,j}, С_{6,k}, С_{7,m}
    (вершины 4, 5, 6 и 7 находятся на одном уровне), где i пробегает всех потомков вершины 4, 
    j --- всех потомков вершины 5,  k --- всех потомков вершины 6, j --- всех потомков вершины 7. 
    Таким образом, элемент beOffsetAKey[0][3] (равен 35) равен количеству всех ключей для h=3.
    Для остальных h значения подстчитываются аналогично.

    Данный массив может использоваться для оценки оперативной памяти, который требуется 
    для формирования ключей.
*/
u32 beOffsetAKey[23][26]={
    {1,  15,  27,  35,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  
        0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  31,  59,  83,  99,  0,  0,  0,  0,  0,  0,  0,  0,  0,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  63,  123,  179,  227,  259,  0,  0,  0,  0,  0,  0,  0,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  127,  251,  371,  483,  579,  643,  0,  0,  0,  0,  0,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  255,  507,  755,  995,  1219,  1411,  1539,  0,  0,  0,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  511,  1019,  1523,  2019,  2499,  2947,  3331,  3587,  0,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  1023,  2043,  3059,  4067,  5059,  6019,  6915,  7683,  8195,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  2047,  4091,  6131,  8163,  10179,  12163,  14083,  15875,  
    17411,  18435,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  4095,  8187,  12275,  16355,  20419,  24451,  28419,  32259,  35843,  
    38915,  40963,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  8191,  16379,  24563,  32739,  40899,  49027,  57091,  65027,  72707,  
    79875,  86019,  90115,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  16383,  32763,  49139,  65507,  81859,  98179,  114435,  130563,  146435,  
    161795,  176131,  188419,  196611,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  32767,  65531,  98291,  131043,  163779,  196483,  229123,  261635,  
    293891,  325635,  356355,  385027,  409603,  425987,  0,  0,  0,  0,  0,  
    0,  0,  0,  0,  0,  0},
    {1,  65535,  131067,  196595,  262115,  327619,  393091,  458499,  523779,  
    588803,  653315,  716803,  778243,  835587,  884739,  917507,  
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  131071,  262139,  393203,  524259,  655299,  786307,  917251,  1048067,  
    1178627,  1308675,  1437699,  1564675,  1687555,  1802243,  1900547,  1966083,  
    0,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  262143,  524283,  786419,  1048547,  1310659,  1572739,  1834755,  2096643,  
    2358275,  2619395,  2879491,  3137539,  3391491,  3637251,  3866627,  4063235,  
    4194307,  0,  0,  0,  0,  0,  0,  0,  0},
    {1,  524287,  1048571,  1572851,  2097123,  2621379,  3145603,  3669763,  4193795,  
    4717571,  5240835,  5763075,  6283267,  6799363,  7307267,  7798787,  8257539,  
    8650755,  8912899,  0,  0,  0,  0,  0,  0,  0},
    {1,  1048575,  2097147,  3145715,  4194275,  5242819,  6291331,  7339779,  8388099,  
    9436163,  10483715,  11530243,  12574723,  13615107,  14647299,  15663107,  
    16646147,  17563651,  18350083,  18874371,  0,  0,  0,  0,  0,  0},
    {1,  2097151,  4194299,  6291443,  8388579,  10485699,  12582787,  14679811,  
    16776707,  18873347,  20969475,  23064579,  25157635,  27246595,  29327363,  
    31391747,  33423363,  35389443,  37224451,  38797315,  39845891,  0,  0,  0,  0,  0},
    {1,  4194303,  8388603,  12582899,  16777187,  20971459,  25165699,  29359875,  
    33553923,  37747715,  41940995,  46133251,  50323459,  54509571,  58687491,  
    62849027,  66977795,  71041027,  74973187,  78643203,  81788931,  83886083,  
    0,  0,  0,  0},
    {1,  8388607,  16777211,  25165811,  33554403,  41942979,  50331523,  58720003,  
    67108355,  75496451,  83884035,  92270595,  100655107,  109035523,  117407747,  
    125763587,  134086659,  142344195,  150470659,  158334979,  165675011,  171966467,  
    176160771,  0,  0,  0},
    {1,  16777215,  33554427,  50331635,  67108835,  83886019,  100663171,  117440259,  
    134217219,  150993923,  167770115,  184545283,  201318403,  218087427,  234848259,  
    251592707,  268304387,  284950531,  301465603,  317718531,  333447171,  348127235,  
    360710147,  369098755,  0,  0},
    {1,  33554431,  67108859,  100663283,  134217699,  167772099,  201326467,  234880771,  
    268434947,  301988867,  335542275,  369094659,  402644995,  436191235,  469729283,  
    503250947,  536739843,  570163203,  603455491,  636485635,  668991491,  700448771,  
    729808899,  754974723,  771751939,  0},
    {1,  67108863,  134217723,  201326579,  268435427,  335544259,  402653059, 
    469761795, 536870403,  603978755,  671086595,  738193411,  805298179, 872398851,  
    939491331,  1006567427,  1073610755,  1140588547,  1207435267,  1274019843,  
    1340080131,  1405091843,  1468006403,  1526726659,  1577058307,  1610612739}};


/*
Зашифрование данных по алгоритму BelT в режиме простой замены.
*/
static err_t beEncryptE( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData );

/*
Расшифрование данных по алгоритму BelT в режиме простой замены.
*/
static err_t beDecryptE( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData );

/*
Вычисление имитовставки данных по алгоритму BelT.
*/
static err_t beImito( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData );

/*
Тиражирование (преобразование) ключа по алгоритму BelT.
*/
static err_t beKeyRep( u8 *pSrcKey, u32 lenKey, u32 * pSrcLevel, u32 * pSrcHdr, u8 *pDst );

/*
Одновременное шифрование и вычисление имитовставки данных по алгоритму BelT.
*/
static err_t beDataWrap( u8 *pKey, u32 lenKey, u8 *pSynhro, u8 *pSrc, u8 *pDst, u32 lenData );

/*
Одновременное расшифрование и проверка имитовставки данных по алгоритму BelT.
*/
static err_t beDataUnwrap( u8 *pKey, u32 lenKey, u8 *pSynhro, u8 *pSrc, u8 *pDst, u32 lenData );

/*
Функция на основании ключа центра передачи S генерирует ключи всех пользователей 
(реализует шаги 1-4 алгоритма формирования  ключей пользователей) и сохраняет 
их по указателю pAKeys. При этом количество всех ключей записывается по указателю pCount. 
В случае, если pAKeys == NULL функция не выполняет алгоритм, а возвращает в pCount 
количество всех ключей.
*/
err_t beGenUsersKeys(u8 h, u16 m, u8 *S, beUserKey *pAKeys, u32 *pCount)
{
    u32    ret, i, j, d, t, n, count;
    u32    Lvl[3];    /* уровень ключа */
    u32    Hdr[4];    /* заголовок ключа */
    u8    A[32];
    u8    sizeKey;
    u8 *   pInitKey;
    beUserKey *pUKey, *pOutKey1, *pOutKey2;
    u8 * pTempKeys; /* массив временных ключей */
    
    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    if (pCount == NULL) 
        return ERR_INVALID_PARAMETER;
    *pCount = beOffsetAKey[h-3][h]; /* количество всех ключей */
    if (pAKeys == NULL) 
        return ERR_OK;
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if (S == NULL) 
        return ERR_INVALID_PARAMETER;
    
    sizeKey = (u8)(m/8);
    n = 1<<h;
    *pCount = beOffsetAKey[h-3][h]; /* количество всех ключей */
    
    /* шаг 2*/
    memSet(Lvl, 0, sizeof(Lvl));
    memSet(Hdr, 0, sizeof(Hdr));
    ret = beKeyRep(S, sizeKey, Lvl, Hdr, A);
    if (ret != ERR_OK) 
        return ret;
    
    /* особый случай: все пользователи разрешены */
    pUKey = pAKeys;
    /* вычислим и сохраним ключ пользователя для особого случая (шаг 3)*/
    pUKey->a = 0; 
    pUKey->b = 0;
    Lvl[0] = 1;
    ret = beKeyRep(A, sizeKey, Lvl, Hdr, pUKey->key);
    memSet(A, 0, sizeof(A));
    if (ret != ERR_OK) 
        return ret;
    
    /* выделим память под временные ключи */
    pTempKeys =  memAlloc(sizeKey*n);
    if (pTempKeys == NULL) 
        return ERR_NOT_ENOUGH_MEMORY;
    
    memcpy(pTempKeys, pUKey->key, sizeKey);
    
    /* вычислим остальные ключи*/
    for (i=1; i<n; i++) /* шаг 4*/
    {
        Lvl[0] = 0; 
        Hdr[0] = i;
        ret = beKeyRep(S, sizeKey, Lvl, Hdr, pTempKeys+i*sizeKey);
        if (ret != ERR_OK) 
        {
            memSet(pTempKeys, 0, sizeKey*n);
            memFree(pTempKeys);
            return ret;
        }
        d = beGetDepth(i);
        for (t=0; t<h-d; t++)
            for (j=(1<<t)*i; j<(1<<t)*i+(1<<t); j++)
            {
                count = beOffsetAKey[h-3][d]+j-(1<<(d+1));
                if (i==j)
                    pInitKey = pTempKeys+i*sizeKey;
                else
                {
                    pUKey = pAKeys + count;
                    pInitKey = pUKey->key;
                }
                pOutKey1 = pAKeys + count + j;
                pOutKey2 = pAKeys + count + j + 1;
                Lvl[0] = t+1;
                Hdr[0] = 1;
                pOutKey1->a = i; 
                pOutKey1->b = 2*j;
                ret = beKeyRep(pInitKey, sizeKey, Lvl, Hdr, pOutKey1->key);
                if (ret != ERR_OK) 
                {
                    memSet(pTempKeys, 0, sizeKey*n);
                    free(pTempKeys);
                    return ret;
                }
                Hdr[0] = 2;
                pOutKey2->a = i; 
                pOutKey2->b = 2*j+1;
                ret = beKeyRep(pInitKey, sizeKey, Lvl, Hdr, pOutKey2->key);
                if (ret != ERR_OK) 
                {
                    memSet(pTempKeys, 0, sizeKey*n);
                    free(pTempKeys);
                    return ret;
                }
            }        
    }
    memSet(pTempKeys, 0, sizeKey*n);
    free(pTempKeys);
    return ERR_OK;
}

/*
Функция на основании номера пользователя u выбирает из массива ключей всех 
пользователей pAKeys ключи для пользователя u (реализует шаг 5 алгоритма 
формирования ключей пользователей) и сохраняет их по указателю pUKeys. 
При этом количество ключей пользователя записывается по указателю pCount. 
В случае, если pUKeys = NULL функция не выполняет алгоритм, а возвращает 
в pCount количество ключей для пользователя (при этом pAKeys может быть NULL). 
Ключи для массива pAKeys должны быть сформированы с помощью функции beGenUsersKeys.
*/    
err_t beGetUserKeys(u8 h, u16 m, u32 u, beUserKey *pAKeys, beUserKey *pUKeys, u32 *pCount)
{
    u32    n; 
    u32    v[BE_MAX_HEIGHT+1];
    u32    count;
    u8    sizeKey;
    u8    i, j, d;
    int        t;
    beUserKey *pUKey;
    
    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    n = 1 << h; /* 2^h */
    if (pCount == NULL) 
        return ERR_INVALID_PARAMETER;
    *pCount = h*(h+1)/2+1; /* количество ключей пользователя */
    if (pUKeys == NULL) 
        return ERR_OK;
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if (pAKeys == NULL) 
        return ERR_INVALID_PARAMETER;
    if ((u == 0) || (u > n)) 
        return ERR_INVALID_PARAMETER;
    
    pUKey = pAKeys;
    sizeKey = (u8)(m/8);
    
    /* скопируем ключ C_{0,0}*/
    memcpy(pUKeys->key, pUKey->key, sizeKey); 
    pUKeys->a = 0;
    pUKeys->b = 0;
    pUKeys++;
    
    /* вычислим путь из листа в корень*/
    v[h] = u+n-1; /* номер листа, соответствующего номеру пользователя */
    for (t=h-1; t>=0; t--)
        v[t] = v[t+1]/2; 
    
    /* скопируем требуемые ключи */
    for (i=0; i<h; i++)
    {
        d = beGetDepth(v[i]);
        for (j=i; j<h; j++)
        {
            count = beOffsetAKey[h-3][d]+2*v[j]-(1<<(d+1));
            pUKeys->a = v[i];
            if (v[j+1] == 2*v[j])
            {
                pUKey = pAKeys+count+1;
                pUKeys->b = 2*v[j]+1;
            }
            else
            {
                pUKey = pAKeys+count;
                pUKeys->b = 2*v[j];
            }
            memcpy(pUKeys->key, pUKey->key, sizeKey);
            pUKeys++;
        }
    }
    
    return ERR_OK;
}

/*
Функция на основании множества запрещенных пользователей R формирует сообщение Х_1 
протокола широковещательного шифрования (pBX) и записывает по адресу pSize размер 
сформированного сообщения (соответствует шагам 1.2, 1.3 протокола). 
Если pBX = NULL функция не формирует сообщение, а возвращает в pSize максимально 
возможный размер сообщения pBX в байтах (для заданного множества запрещенных 
пользователей R).
В массиве R последовательные номера битов соответствуют последовательным номерам 
пользователей, при этом самый младший бит соответствует пользователю c номером 1. 
Если бит установлен в 1, то пользователь является запрещенным. 
Все пользователи не могут быть запрещенными.
*/
err_t beFormBMsgX(u8 h, u8 *R, u32 *r, u8 *pBX, u32 *pSize)
{
    u32 size_d, size_p, d, ret, p, q;
    
    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    if ((pSize == NULL) || (R == NULL)) 
        return ERR_INVALID_PARAMETER;
    
    size_d = BE_SIZE_D(h);
    size_p = BE_SIZE_P(h);
    
    if (pBX == NULL)
    {/* определим максимальный размер буфера для сообщения X1 */
        *r = beGetCountLeaves(R, BE_SIZE_LEAVES(h), &p, &q);
        if (*r == 0) 
            d = BE_COUNT_COVER(1);
        else
            d = BE_COUNT_COVER(*r);
        
        *pSize = size_d + d*2*size_p;
        return ERR_OK;
    }
    else
    {/* определим минимальный размер буфера для сообщения X1 */
        if (*pSize < size_d + 2*size_p) 
            return ERR_INVALID_PARAMETER;
    }
    
    *r = 0;
    ret = beCreateIdsCover(h, r, R, &d, pBX+size_d);
    if (ret != ERR_OK) 
        return ret;
    
    memcpy(pBX, &d, size_d);
    *pSize = size_d+2*d*size_p;
    return ERR_OK;
}

/*
Функция на основании сообщения Х_1 (pBX), ключа центра передачи данных S, 
сеансового ключа защиты данных K протокола широковещательного шифрования формирует сообщение, 
являющееся конкатанацией сообщений Х_2, X_3, …,X_{d+2} протокола (окончание сообщения X) и 
записывает по адресу pSize размер сформированного сообщения (соответствует шагу 1.3 протокола). 
Если pEX = NULL функция не формирует сообщение, а возвращает в pSize максимально возможный размер 
сообщения pEX в байтах. При этом размер определяется на основании pBX или R (если pBX = NULL). 
При задании pBX размер определяется точно, а если pBX = NULL, то определяется максимально 
возможный размер.
Сообщение, которое передается в pBX должно быть сформировано с помощью функции beFormBMsgX.
*/
err_t beFormEMsgX(u8 h, u16 m, u8 *S, u8 *K, u32 r, u8 *pBX, u8 *pEX, u32 *pSize)
{
    u32 i, t, offsetC, size_d, size_p, size_key, size, d, ret, p, q, a;
    u8    A[32];
    u32    Lvl[3];    /* уровень ключа */
    u32    Hdr[4];    /* заголовок ключа */
    u32    v[BE_MAX_HEIGHT+1];

    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if (pSize == NULL) 
        return ERR_INVALID_PARAMETER;
    if ((pEX != NULL) && (pBX == NULL)) 
        return ERR_INVALID_PARAMETER;

    size_d = BE_SIZE_D(h);
    size_p = BE_SIZE_P(h);
    size_key = m/8;
    
    if ((pEX == NULL) && (pBX == NULL))
    {/* определим максимальный размер буфера для сообщения X2 */
        if (r == 0) 
            d = BE_COUNT_COVER(1);
        else
            d = BE_COUNT_COVER(r);

        *pSize = BE_SIZE_IMITO + d*size_key;
        return ERR_OK;
    }
    else if ((pEX == NULL) && (pBX  != NULL))
    {
        d = 0;
        memcpy(&d, pBX, size_d);
        *pSize = BE_SIZE_IMITO + d*size_key;
        return ERR_OK;
    }
    else
    {/* определим минимальный размер буфера для сообщения X2 */
        if (*pSize < BE_SIZE_IMITO + size_key) 
            return ERR_INVALID_PARAMETER;
    }

    d = 0;
    memcpy(&d, pBX, size_d);
    ret = beImito(K, size_key, pBX, pEX, size_d + d*2*size_p);
    if (ret != ERR_OK) 
        return ret;
    size = BE_SIZE_IMITO; 
    offsetC = size_d;

    memSet(Lvl, 0, sizeof(Lvl));
    memSet(Hdr, 0, sizeof(Hdr));

    if (r == 0)
    {/* особый случай */ 
        if (d != 1) 
            return ERR_INTERNAL;
        p = q = 0;
        memcpy(&p, pBX + offsetC, size_p); offsetC += size_p;    
        memcpy(&q, pBX + offsetC, size_p); offsetC += size_p;    
        if ((p != 0) && (q != 0)) 
            return ERR_INTERNAL;
        
        ret = beKeyRep(S, size_key, Lvl, Hdr, A);
        if (ret != ERR_OK) 
        {    
            memSet(A,0, sizeof(A));
            return ret;
        }
        
        Lvl[0] = 1;
        ret = beKeyRep(A, size_key, Lvl, Hdr, A);
        if (ret != ERR_OK) 
        {    
            memSet(A,0, sizeof(A));
            return ret;
        }
        
        Lvl[0] = 2;
        ret = beKeyRep(A, size_key, Lvl, Hdr, A);
        if (ret != ERR_OK) 
        {    
            memSet(A,0, sizeof(A));
            return ret;
        }

        ret = beEncryptE(A, size_key, K, pEX+size, size_key);
        size += size_key;
        *pSize = size;
        memSet(A,0, sizeof(A));
        return ret;    
    }
    
    
    for (t=0; t<d; t++)
    {
        p = q = 0;
        memcpy(&p, pBX + offsetC, size_p); 
        offsetC += size_p;    
        memcpy(&q, pBX + offsetC, size_p); 
        offsetC += size_p;    
        Lvl[0] = 0;
        Hdr[0] = p;
        ret = beKeyRep(S, size_key, Lvl, Hdr, A);
        if (ret != ERR_OK) 
        {    
            memSet(A,0, sizeof(A));
            return ret;
        }
        a = beGetDepth(q)-beGetDepth(p)+1;
        v[a-1] = q;
        for (i=a-1; i>=1; i--)
            v[i-1] = v[i]/2;
        
        for (i=1; i<a; i++)
        {
            if (v[i]==2*v[i-1])
                Hdr[0] = 1;
            else
                Hdr[0] = 2;
            Lvl[0] = i;
            ret = beKeyRep(A, size_key, Lvl, Hdr, A);
            if (ret != ERR_OK) 
            {    
                memSet(A,0, sizeof(A));
                return ret;
            }
        }
        
        Hdr[0] = 0;
        Lvl[0] = a;
        
        ret = beKeyRep(A, size_key, Lvl, Hdr, A);
        if (ret != ERR_OK) 
        {
            memSet(A,0, sizeof(A));
            return ret;
        }

        ret = beEncryptE(A, size_key, K, pEX+size, size_key);
        if (ret != ERR_OK) 
        {
            memSet(A,0, sizeof(A));
            return ret;
        }
        size += size_key;
    }
    
    *pSize = size;
    memSet(A,0, sizeof(A));
    return ERR_OK;
}

/*
Функция на основании сообщения M и сеансового ключа защиты данных K протокола 
широковещательного шифрования формирует сообщение Y (соответствует шагу 1.5 протокола), 
и записывает по адресу pSizeAY размер сформированного сообщения. 
Если pAY = NULL функция не формирует сообщение, а возвращает в pSizeAY требуемый 
размер буфера pAY в байтах (размер определяется на основании параметра SizeM).
*/
err_t beFormAMsgY(u32 m, u8 *K, u8 *T, u8 *M, u32 SizeM, u8 *pAY, u32 *pSizeAY)
{
    u32 ret;
    
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if ((pSizeAY == NULL) || (SizeM == 0))
        return ERR_INVALID_PARAMETER;

    *pSizeAY = SizeM + BE_SIZE_IMITO + BE_SIZE_SYNHRO;    

    if (pAY == NULL) 
        return ERR_OK; /* информационный режим */

    if ((K == NULL) || (T == NULL) || (M == NULL) || (pAY == NULL)) 
        return ERR_INVALID_PARAMETER;

    memcpy(pAY, T, BE_SIZE_SYNHRO); 
    ret = beDataWrap(K, m/8, T, M, pAY+BE_SIZE_SYNHRO, SizeM); 
    if (ret != ERR_OK)
        return ERR_INTERNAL;
    else 
        return ERR_OK;
}

/*
Функция производит для пользователя u разбор сообщения Х_1 (pBX) протокола и формирует на основании 
массива ключей пользователей pUKeys ключ снятия защиты pDKey и определяет номер e, 
который будет использоваться при расшифровании сеансового ключа (соответствует шагу 2.1 протокола). 
Дополнительно функция извлекает из сообщения Х_1 параметр d. 
Если пользователь u является запрещенным, то функция возвращает код ошибки BEE_ERR_REVOKE.
*/
err_t beAnalyzBMsgX(u8 h, u16 m, u32 u, beUserKey *pUKeys,  
                       u8 *pBX, u32 SizeBX, u32 *d, u32 *pE, u8 *pDKey)
{
    u32    n, ret, size_id, size_p, t, CntKeyInfo; 
    u32    k=0, e=0, count=0, a, aa=0, b, c, da, db, j, offset, ea, eb;
    u32    v[BE_MAX_HEIGHT+1], tau[BE_MAX_HEIGHT+1];
    u32    Lvl[3];    /* уровень ключа */
    u32    Hdr[4];    /* заголовок ключа */
    u32    beOffsetUKey[BE_MAX_HEIGHT+1]; /* сдвиги для быстрого поиска ключей */
    u8 *   pKeyInfo = NULL;
    bool_t    flag = FALSE, flag2 = FALSE;
    u8    size_key;
    u8    A[32];
    
    if ((pUKeys == NULL) || (pBX == NULL) || (pE == NULL) || (pDKey == NULL) || (d == NULL)) 
        return ERR_INVALID_PARAMETER;
    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    n = 1 << h;
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if ((u == 0) || (u > n)) 
        return ERR_INVALID_PARAMETER;    

    size_id = BE_SIZE_D(h);
    size_p = BE_SIZE_P(h);
    size_key = (u8)(m/8);
    CntKeyInfo = 0;
    memcpy(&CntKeyInfo, pBX, size_id);

    if ((CntKeyInfo == 0) || (CntKeyInfo > 2*n-4)) 
        return ERR_BAD_FORMAT;
    if (SizeBX != size_id+2*CntKeyInfo*size_p) 
        return ERR_BAD_FORMAT;

    pKeyInfo = pBX+size_id;

    /* подсчитаем сдвиги, необходимые для быстрого поиска ключей*/
    beOffsetUKey[0] = 1;
    for (j=0; j<h; j++)
        beOffsetUKey[j+1]=beOffsetUKey[j]+h-j;

    c = u+n-1;
    offset = 0;

    memSet(Lvl, 0, sizeof(Lvl));
    memSet(Hdr, 0, sizeof(Hdr));

    for (t=0; t<CntKeyInfo; t++)
    {
        a = b = 0;
        memcpy((u8 *) &a, pKeyInfo + offset, size_id); offset += size_id;
        memcpy((u8 *) &b, pKeyInfo + offset, size_id); offset += size_id;

        if ((a == 0) && (b == 0))
        { /* шаг 2.1 (особый случай)*/
            k = 2;
            e = t;
            count = 0; /* номер ключа С_{0,0} в наборе всех ключей  */
            /* проверим корректность набора*/
            if (((pUKeys+count)->a != a) || ((pUKeys+count)->b != b))
                return ERR_INTERNAL; /* плохой набор */
            flag = TRUE;
            break;
        }
        ret  = beCheckLeaf(h, a, b, c);
        if (ret == ERR_OK)
        {
            e = t; /* шаг 2.2.a*/
            if ((b == 2*a) || (b == 2*a+1))
            { /* шаг 2.2.b*/
                k = 2; 
                da = beGetDepth(a);
                count = beOffsetUKey[da];/* номер ключа С_{a,b} в наборе ключей пользователя*/
                /* проверим корректность набора*/
                if (((pUKeys+count)->a != a) || ((pUKeys+count)->b != b))
                    return ERR_INTERNAL; /* плохой набор */
                flag = TRUE;
            }
            break;
        }
        else if (ret != ERR_REVOKED) return ret;
    }

    /* шаг 3*/
    if (t == CntKeyInfo) return ERR_REVOKED;

    if (flag != TRUE)
    { /* шаги 4-10 */
        ea = eb = 0;
        memcpy((u8 *)&ea, pKeyInfo+e*2*size_id, size_id);
        memcpy((u8 *)&eb, pKeyInfo+e*2*size_id+size_id, size_id);
        a = beGetDepth(c)-beGetDepth(ea)+1;
        v[a-1] = c;
        for (t=a-1; t>=1; t--)
            v[t-1] = v[t]/2;
    
        b = beGetDepth(eb)-beGetDepth(ea)+1;
        tau[b-1] = eb;
        for (t=b-1; t>=1; t--)
        { /* шаг 9*/
            tau[t-1] = tau[t]/2;
            for (j=1; j<a; j++)
            {
                if (tau[t-1] == v[j-1])
                {    
                    da = beGetDepth(ea);
                    db = beGetDepth(tau[t]);
                    count = beOffsetUKey[da]+db-da-1;/* номер ключа С_{a,b} в наборе ключей пользователя*/
                    aa = t+1;
                    k = db-da+1;
                    flag2 = TRUE;
                    break;
                }
            }
            if (flag2) break;
        }
        if (flag2 != TRUE) 
            return ERR_INTERNAL; /* некорректно запрограммирован алгоритм!!!*/

        /* шаг 10*/
        memcpy(A, (pUKeys+count)->key,  size_key);
        Lvl[0] = 0;
        Hdr[0] = 0;
        for (t=aa; t<b; t++)
        {
            if (tau[t]==2*tau[t-1])
                Hdr[0] = 1;
            else
                Hdr[0] = 2;
            Lvl[0] = k;
            ret = beKeyRep(A, size_key, Lvl, Hdr, A);
            if (ret != ERR_OK) 
            {    
                memSet(A,0, sizeof(A));
                return ret;
            }
            k++;
        }
    }
    /* шаг 11*/
    if (flag) memcpy(A, (pUKeys+count)->key,  size_key);
    Hdr[0] = 0;
    Lvl[0] = k;

    ret = beKeyRep(A, size_key, Lvl, Hdr, pDKey);
    if (ret != ERR_OK) 
    {
        memSet(A,0, sizeof(A));
        return ret;
    }

    *pE = e+1;
    *d = CntKeyInfo;
    memSet(A,0, sizeof(A));

    return ERR_OK;
}

/*
Функция на основании номера ключа снятия защиты (E) и ключа снятия защиты (pDkey) производит разбор 
сообщения, являющегося конкатанацией сообщений Х2, X3, …, Xd+2 протокола (окончание сообщения X), 
расшифровывает и возвращает сеансовый ключ K. 
Дополнительно функция возвращает имитовставку сообщения X соответствует сообщению Х2). 
*/
err_t beAnalyzEMsgX(u16 m, u8 *pEX, u32 SizeEX, u32 d, u32 E, u8 *pDKey, u8 *pK, u8 *pImito)
{
    u32 ret;

    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if ((pEX == NULL) || (pDKey == NULL) || (pK == NULL) || (pImito == NULL)) 
        return ERR_INVALID_PARAMETER;
    if ((d == 0) || (SizeEX == 0) || (E == 0)) 
        return ERR_INVALID_PARAMETER;
    if (d*m/8 + BE_SIZE_IMITO != SizeEX) 
        return ERR_INVALID_PARAMETER;
    if (E > d) 
        return ERR_INVALID_PARAMETER;

    ret = beDecryptE(pDKey, m/8, pEX+BE_SIZE_IMITO+((E-1)*m/8), pK, m/8); 
    if (ret != ERR_OK)
        return ERR_INTERNAL;

    memcpy(pImito, pEX, BE_SIZE_IMITO); 

    return ERR_OK;
}

/*
Функция проверяет на основании сеансового ключа K и имитовставки (Imito) 
целостность сообщения Х_1 pBX).
Cоответствует шагам 2.2, 2.3 протокола
Если целостность сообщения X1 не нарушена, то возвращается код ошибки ERR_OK, 
иначе функция возвращает код ошибки ERR_BAD_MAC.
*/
err_t beCheckMsgX(u8 h, u16 m, u8 *pBX, u32 SizeBX, u8 *pK, u8 *pImito)
{
    u32    n, ret;
    u8    imi[BE_SIZE_IMITO];
        
    if ((h < 3) || (h > BE_MAX_HEIGHT)) 
        return ERR_INVALID_PARAMETER;
    n = 1 << h;
    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if ((pBX == NULL) || (pK == NULL) || (pImito == NULL)) 
        return ERR_INVALID_PARAMETER;
    if (SizeBX < BE_SIZE_D(h)+2*BE_SIZE_P(h)) 
        return ERR_INVALID_PARAMETER;

    ret = beImito(pK, m/8, pBX, imi, SizeBX);
    if (ret != ERR_OK)
        return ERR_INTERNAL;

    if (memcmp(imi, pImito, BE_SIZE_IMITO)) 
        return ERR_BAD_MAC;

    return ERR_OK;
}

/*
Функция на основании сеансового ключа защиты данных K извлекает из сообщения Y, 
расшифровывает и проверяет имитовставку исходных данных, 
т.е. данных M, которые соответствуют сообщению Y2 (соответствует шагам 2.4 - 2.6 протокола). 
Если целостность данных не нарушена, то возвращается код ошибки ERR_OK, 
иначе функция возвращает код ошибки ERR_BAD_MAC. 
Если M=NULL функция возвращает требуемый размер буфера M в pSizeM.
*/
err_t beAnalyzAMsgY(u16 m, u8 *pK, u8 *pAY, u32 SizeAY, u8 *M, u32 *pSizeM)
{
    u32 ret;

    if ((m != 128) && (m != 192) && (m != 256)) 
        return ERR_INVALID_PARAMETER;
    if ((SizeAY < BE_SIZE_IMITO + BE_SIZE_SYNHRO + 1) || (pSizeM == NULL))
        return ERR_INVALID_PARAMETER;

    if (M == NULL)
    {
        *pSizeM = SizeAY - BE_SIZE_IMITO - BE_SIZE_SYNHRO; 
        return ERR_OK;
    }

    ret = beDataUnwrap(pK, m/8, pAY, pAY+BE_SIZE_SYNHRO, M, SizeAY-BE_SIZE_SYNHRO); 
    if (ret == ERR_BAD_MAC)
        return ERR_BAD_MAC;
    else if (ret != ERR_OK)
        return ERR_INTERNAL;
    
    *pSizeM  = SizeAY - BE_SIZE_IMITO - BE_SIZE_SYNHRO; 
    
    return ERR_OK;
}



/*
Зашифрование данных по алгоритму BelT в режиме простой замены.
*/
static err_t beEncryptE( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData )
{
    return beltECBEncr( pDst, pSrc, lenData, pKey, lenKey );
}

/*
Расшифрование данных по алгоритму BelT в режиме простой замены.
*/
static err_t beDecryptE( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData )
{
    return beltECBDecr( pDst, pSrc, lenData, pKey, lenKey );
}

/*
Вычисление имитовставки данных по алгоритму BelT.
*/
static err_t beImito( u8 *pKey, u32 lenKey, u8 *pSrc, u8 *pDst, u32 lenData )
{
    return beltMAC( pDst, pSrc, lenData, pKey, lenKey );
}

/*
Тиражирование (преобразование) ключа по алгоритму BelT.
*/
static err_t beKeyRep( u8 *pSrcKey, u32 lenKey, u32 * pSrcLevel, u32 * pSrcHdr, u8 *pDst )
{
    return beltKRP( pDst, lenKey, pSrcKey, lenKey, (u8 *)pSrcLevel, (u8 *)pSrcHdr );
}

/*
Одновременное шифрование и вычисление имитовставки данных по алгоритму BelT.
*/
static err_t beDataWrap( u8 *pKey, u32 lenKey, u8 *pSynhro, u8 *pSrc, u8 *pDst, u32 lenData )
{
    return beltDWPWrap( pDst, pDst + lenData, pSrc, lenData, NULL, 0, pKey, lenKey, pSynhro );
}

/*
Одновременное расшифрование и проверка имитовставки данных по алгоритму BelT.
*/
static err_t beDataUnwrap( u8 *pKey, u32 lenKey, u8 *pSynhro, u8 *pSrc, u8 *pDst, u32 lenData )
{
    return beltDWPUnwrap( pDst, pSrc, lenData - 8, NULL, 0, pSrc + lenData - 8, pKey, lenKey, pSynhro );
}
