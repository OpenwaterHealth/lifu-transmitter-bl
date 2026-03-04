
#ifndef INC_COMMON_H_
#define INC_COMMON_H_

#include "version.h"

#include <stdint.h>
#include <stdbool.h>


#ifndef FW_VERSION
#define FW_VERSION "unknown"
#endif
#ifndef FW_SHA
#define FW_SHA "unknown"
#endif
#ifndef FW_BUILD_TIME
#define FW_BUILD_TIME "unknown"
#endif

#define FW_VERSION_STRING FW_VERSION
#define FW_SHA_STRING FW_SHA
#define FW_BUILD_TIME_STRING FW_BUILD_TIME

#endif /* INC_COMMON_H_ */

