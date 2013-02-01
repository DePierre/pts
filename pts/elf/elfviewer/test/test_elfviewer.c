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
	elfFile = fopen ( "./hello" , "r" );
	TEST_ASSERT_EQUAL_STRING("MaChaine",getMachine(elfFile));
}
 