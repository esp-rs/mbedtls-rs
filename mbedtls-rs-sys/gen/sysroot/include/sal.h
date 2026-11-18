#ifndef __SAL_H__
#define __SAL_H__

/*
 * The part of MSVC's <sal.h> MbedTLS uses: `platform_util.h` includes it when
 * `_MSC_VER` is defined and `__GNUC__` is not, which is the case of clang
 * targeting `*-windows-msvc`. The annotation only helps static analysis.
 */
#define _Check_return_

#endif
