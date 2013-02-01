#include "unity.h"
#include "peviewer.h"
#include <pestruct.h>

void setUp(void)
{
}

void tearDown(void)
{
}

void test_is_pe(void)
{
	
	
	TEST_ASSERT_EQUAL_INT(1, is_pe("/home/maijin/packthatshit/pts/pe/peviewer/test/note.exe"));
}

void test_getDosHeader(void)
{	
	TEST_ASSERT_EQUAL(0x5A4D,get_dos_header("/home/maijin/packthatshit/pts/pe/peviewer/test/note.exe")->e_magic);
}
