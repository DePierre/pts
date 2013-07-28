#ifndef ERRORS_H
#define ERRORS_H

#define SUCCESS 0 /**< Everything went fine @hideinitializer */

/* Errors from the STD */
#define FILE_ERROR -1 /**< Error about the file @hideinitializer */
#define ALLOCATION_ERROR -2 /**< Error about allocations @hideinitializer */
#define NULL_POINTER -3 /**< Error when a pointer is NULL @hideinitializer */

/* Errors from PEVIEWER */
#define NO_FREE_SPACE_IN_SECTIONS_HEADERS -100 /**< Error when there is no free space for a new section header @hideinitializer */
#define NO_FREE_SPACE_IN_SECTION -101 /**< Error when there is no free space for code in the section @hideinitializer */
#define DOS_HEADER_ERROR -102 /**< Error when the DOS header can't be dump @hideinitializer */
#define PE_HEADER_ERROR -103 /**< Error when the PE header can't be dump @hideinitializer */
#define COFF_HEADER_ERROR -104 /**< Error when the COFF header can't be dump @hideinitializer */
#define NO_CODE_SECTION_FOUND -105 /**< Error when the code section cannot be found @hideinitializer */
#define INVALID_PE_SIGNATURE -106 /**< Error when the PE signature is invalid @hideinitializer */
#define OBJ_FILE -107 /**< Error when the file is an OBJ file @hideinitializer */
#define NOT_EXECUTABLE -108 /**< Error when the file is not an executable file @hideinitializer */

/* Errors from PEPACKER */

#endif /* ERRORS_H */
