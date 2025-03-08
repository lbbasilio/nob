#ifndef NOB_H_
#define NOB_H_

#include <stddef.h>
#include <stdbool.h>

#ifndef NOB_MAX_LEN
#define NOB_MAX_LEN 0x1000
#endif // NOB_MAX_LEN

typedef struct {
	char str[NOB_MAX_LEN + 1];
	size_t len;
} Nob_Cmd;

#define nob_cmd_append(cmd, ...) __nob_cmd_append(cmd, __VA_ARGS__, NULL)
void __nob_cmd_append(Nob_Cmd* cmd, ...);
void nob_cmd_reset(Nob_Cmd* cmd);
bool nob_cmd_run(Nob_Cmd* cmd);

#endif // NOB_H_

#ifdef NOB_IMPLEMENTATION

#include <stdio.h>
#include <stdarg.h>
#include <windows.h>

void __nob_cmd_append(Nob_Cmd* cmd, ...)
{
	va_list arg_list;
	va_start(arg_list, cmd);

	char* token = va_arg(arg_list, char*);
	while (token) {
		size_t len = strlen(token);
		if (cmd->len + len + 1 > NOB_MAX_LEN)
		{
			printf("[ERROR] Command exceeds maximum length\n%s", cmd->str);
			va_end(arg_list);
			exit(1);
		}

		if (cmd->len > 0) 
			cmd->str[cmd->len++] = ' ';

		memcpy(cmd->str + cmd->len, token, len);
		cmd->len += len;
		token = va_arg(arg_list, char*);
	}

	va_end(arg_list);
	return;
}

void nob_cmd_reset(Nob_Cmd* cmd)
{
	cmd->str[0] = '\0';
	cmd->len = 0;
}

bool nob_cmd_run(Nob_Cmd* cmd)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&sa, sizeof(sa));
	si.cb = sizeof(si);

	// Allow child process to inherit the created pipe
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;

	// Create pipe to read stdout and stderr
	HANDLE child_read_handle, child_write_handle;
	CreatePipe(&child_read_handle, &child_write_handle, &sa, 0);
	SetHandleInformation(&child_read_handle, HANDLE_FLAG_INHERIT, 0);

	si.hStdError = child_write_handle;
	si.hStdOutput = child_write_handle;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	printf("[CMD] %s\n", cmd->str);

	// Spawn child process
	CreateProcess(NULL,
		cmd->str,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&si,
		&pi);

	// Wait for it to finish
	WaitForSingleObject(pi.hProcess, INFINITE);

	DWORD exit_code;
	GetExitCodeProcess(pi.hProcess, &exit_code);

	// Cleanup
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// Must close the write handle, or else the following read will hang
	CloseHandle(child_write_handle); 

	// Read output
	DWORD read_bytes;
	CHAR buffer[0x10000];
	buffer[0] = '\0';
	
	ReadFile(child_read_handle, buffer, sizeof(buffer), &read_bytes, NULL);
	CloseHandle(child_read_handle);

	if (exit_code)
		printf("[ERROR] Compilation terminated with exit code %d\n", exit_code);

	if (strlen(buffer))
		printf("%s\n", buffer);

	return exit_code == 0;
}

#endif // NOB_IMPLEMENTATION
