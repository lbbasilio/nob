#define NOB_IMPLEMENTATION
#include "nob.h"

int main() 
{
	Nob_Cmd cmd = {0};
	nob_cmd_append(&cmd, "gcc", "-Wall", "main.c");
	nob_cmd_append(&cmd, "-o", "main.exe");
	if (!nob_cmd_run(&cmd))
		return 1;
	return 0;
}
