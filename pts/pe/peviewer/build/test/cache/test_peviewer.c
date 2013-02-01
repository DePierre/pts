#include "unity.h"
#include "peviewer.h"




void setUp(void)

{

}



void tearDown(void)

{

}



void test_is_pe(void)

{





 UnityAssertEqualNumber((_U_SINT)((1)), (_U_SINT)((is_pe("/home/maijin/packthatshit/pts/pe/peviewer/test/note.exe"))), (((void *)0)), (_U_UINT)17, UNITY_DISPLAY_STYLE_INT);

}



void test_getDosHeader(void)

{

 UnityAssertEqualNumber((_U_SINT)((0x5A4D)), (_U_SINT)((get_dos_header("/home/maijin/packthatshit/pts/pe/peviewer/test/note.exe")->e_magic)), (((void *)0)), (_U_UINT)22, UNITY_DISPLAY_STYLE_INT);

}
