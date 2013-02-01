#include "unity.h"
#include "elfviewer.h"




void setUp(void)

{

}



void tearDown(void)

{

}



void test_getMachine(void)

{

 FILE * elfFile;

 UnityAssertEqualString((const char*)("MaChaine"), (const char*)(getMachine(elfFile)), (((void *)0)), (_U_UINT)16);

}
