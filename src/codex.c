// simplewall modified fork
// Diagnostic-only Codex sandbox identity capture.
// Copyright (c) 2026 simplewall fork contributors
//
// This module must not create, enable, or remove WFP permit filters.

#include "global.h"

typedef struct _CODEX_PROCESS_IDENTITY
{
	PR_STRING process_path;
	PR_STRING parent_chain;
	PR_STRING command_line;

	FILETIME creation_filetime;
	LONG64 creation_time;
	ULONG process_id;

	BOOLEAN is_ambiguous;
} CODEX_PROCESS_IDENTITY, *PCODEX_PROCESS_IDENTITY;

static VOID _app_codex_deleteprocessidentity (
	_Inout_ PCODEX_PROCESS_IDENTITY identity
)
{
	if (identity->process_path)
		_r_obj_dereference (identity->process_path);

	if (identity->parent_chain)
		_r_obj_dereference (identity->parent_chain);

	if (identity->command_line)
		_r_obj_dereference (identity->command_line);

	RtlSecureZeroMemory (identity, sizeof (CODEX_PROCESS_IDENTITY));
}

static BOOLEAN _app_codex_isflagcharacter (
	_In_ WCHAR character
)
{
	return (
		(character >= L'a' && character <= L'z') ||
		(character >= L'A' && character <= L'Z') ||
		(character >= L'0' && character <= L'9') ||
		character == L'-' ||
		character == L'_' ||
		character == L'.'
	);
}

static BOOLEAN _app_codex_issafeflag (
	_In_ PR_STRINGREF flag
)
{
	R_STRINGREF safe_flags[] = {
		PR_STRINGREF_INIT (L"--help"),
		PR_STRINGREF_INIT (L"--version"),
		PR_STRINGREF_INIT (L"--quiet"),
		PR_STRINGREF_INIT (L"--verbose"),
		PR_STRINGREF_INIT (L"--json"),
		PR_STRINGREF_INIT (L"--sandbox"),
		PR_STRINGREF_INIT (L"--search"),
		PR_STRINGREF_INIT (L"--offline"),
		PR_STRINGREF_INIT (L"--approval-policy"),
		PR_STRINGREF_INIT (L"--ask-for-approval"),
		PR_STRINGREF_INIT (L"--model"),
		PR_STRINGREF_INIT (L"--config"),
		PR_STRINGREF_INIT (L"--cd"),
		PR_STRINGREF_INIT (L"--cwd"),
		PR_STRINGREF_INIT (L"--add-dir"),
		PR_STRINGREF_INIT (L"--profile"),
		PR_STRINGREF_INIT (L"--color"),
		PR_STRINGREF_INIT (L"--no-color"),
		PR_STRINGREF_INIT (L"--full-auto"),
		PR_STRINGREF_INIT (L"/help"),
		PR_STRINGREF_INIT (L"/quiet"),
		PR_STRINGREF_INIT (L"/verbose"),
		PR_STRINGREF_INIT (L"/?"),
		PR_STRINGREF_INIT (L"-h"),
		PR_STRINGREF_INIT (L"-V"),
		PR_STRINGREF_INIT (L"-q"),
		PR_STRINGREF_INIT (L"-v"),
		PR_STRINGREF_INIT (L"-m"),
		PR_STRINGREF_INIT (L"-C"),
		PR_STRINGREF_INIT (L"-c"),
	};

	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (safe_flags); i++)
	{
		if (_r_str_isequal (flag, &safe_flags[i], FALSE))
			return TRUE;
	}

	return FALSE;
}

static PR_STRING _app_codex_sanitizecommandline (
	_In_opt_ PR_STRING raw_command_line,
	_In_ PR_STRING process_path
)
{
	R_STRINGBUILDER string_builder;
	R_STRINGREF flag;
	LPWSTR *arguments;
	ULONG_PTR argument_length;
	ULONG_PTR flag_length;
	INT argument_count = 0;
	BOOLEAN is_flag;

	_r_obj_initializestringbuilder (&string_builder, 256);
	_r_obj_appendstringbuilder2 (&string_builder, &process_path->sr);

	arguments = raw_command_line ? CommandLineToArgvW (raw_command_line->buffer, &argument_count) : NULL;

	for (INT i = 1; arguments && i < argument_count; i++)
	{
		argument_length = wcslen (arguments[i]);
		flag_length = 0;
		is_flag = FALSE;

		if (argument_length > 2 && arguments[i][0] == L'-' && arguments[i][1] == L'-')
		{
			flag_length = 2;

			while (
				flag_length < argument_length &&
				arguments[i][flag_length] != L'=' &&
				arguments[i][flag_length] != L':'
			)
			{
				if (!_app_codex_isflagcharacter (arguments[i][flag_length]))
				break;

				flag_length += 1;
			}

			is_flag = (
				flag_length > 2 &&
				(flag_length == argument_length ||
				 arguments[i][flag_length] == L'=' ||
				 arguments[i][flag_length] == L':')
			);
		}
		else if (argument_length > 1 && arguments[i][0] == L'/')
		{
			flag_length = 1;

			while (
				flag_length < argument_length &&
				arguments[i][flag_length] != L'=' &&
				arguments[i][flag_length] != L':'
			)
			{
				if (!_app_codex_isflagcharacter (arguments[i][flag_length]))
					break;

				flag_length += 1;
			}

			is_flag = (
				flag_length > 1 &&
				(flag_length == argument_length ||
				 arguments[i][flag_length] == L'=' ||
				 arguments[i][flag_length] == L':')
			);
		}
		else if (
			argument_length == 2 &&
			arguments[i][0] == L'-' &&
			_app_codex_isflagcharacter (arguments[i][1])
		)
		{
			flag_length = argument_length;
			is_flag = TRUE;
		}

		if (is_flag)
		{
			_r_obj_initializestringref_ex (&flag, arguments[i], flag_length * sizeof (WCHAR));
			is_flag = _app_codex_issafeflag (&flag);
		}

		_r_obj_appendstringbuilder (&string_builder, L" ");

		if (is_flag)
		{
			_r_obj_appendstringbuilder2 (&string_builder, &flag);

			if (flag_length < argument_length)
				_r_obj_appendstringbuilder (&string_builder, L"=<redacted>");
		}
		else
		{
			_r_obj_appendstringbuilder (&string_builder, L"<redacted>");
		}
	}

	if (!arguments)
		_r_obj_appendstringbuilder (&string_builder, L" <command line unavailable>");

	if (arguments)
		LocalFree (arguments);

	return _r_obj_finalstringbuilder (&string_builder);
}

static BOOLEAN _app_codex_stringlistcontains (
	_In_ LPCWSTR config_name,
	_In_opt_ PR_STRING value
)
{
	R_STRINGREF current;
	R_STRINGREF item;
	R_STRINGREF remaining;
	PR_STRING configured_values;
	BOOLEAN is_match = FALSE;

	if (_r_obj_isstringempty (value))
		return FALSE;

	configured_values = _r_config_getstringexpand (config_name, L"", NULL);

	if (_r_obj_isstringempty (configured_values))
	{
		if (configured_values)
			_r_obj_dereference (configured_values);

		return FALSE;
	}

	current = configured_values->sr;

	while (current.length)
	{
		if (_r_str_splitatchar (&current, L';', &item, &remaining))
		{
			current = remaining;
		}
		else
		{
			item = current;
			current.length = 0;
		}

		while (item.length && (item.buffer[0] == L' ' || item.buffer[0] == L'\t'))
			_r_str_skiplength (&item, sizeof (WCHAR));

		while (
			item.length &&
			(item.buffer[(item.length / sizeof (WCHAR)) - 1] == L' ' ||
			 item.buffer[(item.length / sizeof (WCHAR)) - 1] == L'\t')
		)
		{
			item.length -= sizeof (WCHAR);
		}

		if (item.length && _r_str_isequal (&item, &value->sr, TRUE))
		{
			is_match = TRUE;
			break;
		}
	}

	_r_obj_dereference (configured_values);

	return is_match;
}

static VOID _app_codex_addpidcandidate (
	_In_ ULONG pid,
	_Inout_ PULONG candidate_pid,
	_Inout_ PBOOLEAN is_ambiguous
)
{
	if (!pid || *is_ambiguous)
		return;

	if (!*candidate_pid)
	{
		*candidate_pid = pid;
	}
	else if (*candidate_pid != pid)
	{
		*is_ambiguous = TRUE;
		*candidate_pid = 0;
	}
}

static ULONG _app_codex_resolvepid (
	_In_ PITEM_LOG ptr_log,
	_Out_ PBOOLEAN is_ambiguous
)
{
	ULONG candidate_pid = 0;
	ULONG required_size = 0;
	PVOID buffer;

	*is_ambiguous = FALSE;

	if (ptr_log->protocol == IPPROTO_TCP)
	{
		GetExtendedTcpTable (
			NULL,
			&required_size,
			FALSE,
			ptr_log->af,
			TCP_TABLE_OWNER_PID_ALL,
			0
		);

		if (!required_size)
			return 0;

		buffer = _r_mem_allocate (required_size);

		if (GetExtendedTcpTable (
			buffer,
			&required_size,
			FALSE,
			ptr_log->af,
			TCP_TABLE_OWNER_PID_ALL,
			0
		) == NO_ERROR)
		{
			if (ptr_log->af == AF_INET)
			{
				PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)buffer;

				for (ULONG i = 0; i < table->dwNumEntries; i++)
				{
					PMIB_TCPROW_OWNER_PID row = &table->table[i];

					if (
						row->dwLocalAddr == ptr_log->local_addr.S_un.S_addr &&
						row->dwRemoteAddr == ptr_log->remote_addr.S_un.S_addr &&
						_r_byteswap_ushort ((UINT16)row->dwLocalPort) == ptr_log->local_port &&
						_r_byteswap_ushort ((UINT16)row->dwRemotePort) == ptr_log->remote_port
					)
					{
						_app_codex_addpidcandidate (
							row->dwOwningPid,
							&candidate_pid,
							is_ambiguous
						);
					}
				}
			}
			else if (ptr_log->af == AF_INET6)
			{
				PMIB_TCP6TABLE_OWNER_PID table = (PMIB_TCP6TABLE_OWNER_PID)buffer;

				for (ULONG i = 0; i < table->dwNumEntries; i++)
				{
					PMIB_TCP6ROW_OWNER_PID row = &table->table[i];

					if (
						RtlEqualMemory (row->ucLocalAddr, ptr_log->local_addr6.u.Byte, FWP_V6_ADDR_SIZE) &&
						RtlEqualMemory (row->ucRemoteAddr, ptr_log->remote_addr6.u.Byte, FWP_V6_ADDR_SIZE) &&
						_r_byteswap_ushort ((UINT16)row->dwLocalPort) == ptr_log->local_port &&
						_r_byteswap_ushort ((UINT16)row->dwRemotePort) == ptr_log->remote_port
					)
					{
						_app_codex_addpidcandidate (
							row->dwOwningPid,
							&candidate_pid,
							is_ambiguous
						);
					}
				}
			}
		}

		_r_mem_free (buffer);
	}
	else if (ptr_log->protocol == IPPROTO_UDP)
	{
		GetExtendedUdpTable (
			NULL,
			&required_size,
			FALSE,
			ptr_log->af,
			UDP_TABLE_OWNER_PID,
			0
		);

		if (!required_size)
			return 0;

		buffer = _r_mem_allocate (required_size);

		if (GetExtendedUdpTable (
			buffer,
			&required_size,
			FALSE,
			ptr_log->af,
			UDP_TABLE_OWNER_PID,
			0
		) == NO_ERROR)
		{
			if (ptr_log->af == AF_INET)
			{
				PMIB_UDPTABLE_OWNER_PID table = (PMIB_UDPTABLE_OWNER_PID)buffer;

				for (ULONG i = 0; i < table->dwNumEntries; i++)
				{
					PMIB_UDPROW_OWNER_PID row = &table->table[i];

					if (
						row->dwLocalAddr == ptr_log->local_addr.S_un.S_addr &&
						_r_byteswap_ushort ((UINT16)row->dwLocalPort) == ptr_log->local_port
					)
					{
						_app_codex_addpidcandidate (
							row->dwOwningPid,
							&candidate_pid,
							is_ambiguous
						);
					}
				}
			}
			else if (ptr_log->af == AF_INET6)
			{
				PMIB_UDP6TABLE_OWNER_PID table = (PMIB_UDP6TABLE_OWNER_PID)buffer;

				for (ULONG i = 0; i < table->dwNumEntries; i++)
				{
					PMIB_UDP6ROW_OWNER_PID row = &table->table[i];

					if (
						RtlEqualMemory (row->ucLocalAddr, ptr_log->local_addr6.u.Byte, FWP_V6_ADDR_SIZE) &&
						_r_byteswap_ushort ((UINT16)row->dwLocalPort) == ptr_log->local_port
					)
					{
						_app_codex_addpidcandidate (
							row->dwOwningPid,
							&candidate_pid,
							is_ambiguous
						);
					}
				}
			}
		}

		_r_mem_free (buffer);
	}

	return candidate_pid;
}

static PR_STRING _app_codex_getparentchain (
	_In_ ULONG process_id,
	_In_ FILETIME creation_filetime
)
{
	R_STRINGBUILDER string_builder;
	PSYSTEM_PROCESS_INFORMATION process_list;
	PSYSTEM_PROCESS_INFORMATION process;
	PSYSTEM_PROCESS_INFORMATION parent_process;
	PR_STRING process_path;
	HANDLE hprocess;
	FILETIME parent_creation_filetime;
	FILETIME exit_filetime;
	FILETIME kernel_filetime;
	FILETIME user_filetime;
	LARGE_INTEGER current_creation;
	LARGE_INTEGER opened_parent_creation;
	ULONG current_pid = process_id;
	ULONG parent_pid;
	NTSTATUS status;

	current_creation.LowPart = creation_filetime.dwLowDateTime;
	current_creation.HighPart = creation_filetime.dwHighDateTime;

	status = _r_sys_enumprocesses (&process_list);

	if (!NT_SUCCESS (status))
		return NULL;

	_r_obj_initializestringbuilder (&string_builder, 256);

	for (ULONG depth = 0; depth < 8 && current_pid; depth++)
	{
		process = PR_FIRST_PROCESS (process_list);
		parent_process = NULL;
		parent_pid = 0;

		while (process)
		{
			if (HandleToULong (process->UniqueProcessId) == current_pid)
			{
				if (process->CreateTime.QuadPart != current_creation.QuadPart)
				{
					process = NULL;
					break;
				}

				parent_pid = HandleToULong (process->InheritedFromUniqueProcessId);
				break;
			}

			process = PR_NEXT_PROCESS (process);
		}

		if (!process || !parent_pid || parent_pid == current_pid)
			break;

		parent_process = PR_FIRST_PROCESS (process_list);

		while (parent_process)
		{
			if (HandleToULong (parent_process->UniqueProcessId) == parent_pid)
				break;

			parent_process = PR_NEXT_PROCESS (parent_process);
		}

		if (
			!parent_process ||
			parent_process->CreateTime.QuadPart > current_creation.QuadPart
		)
		{
			break;
		}

		process_path = NULL;
		opened_parent_creation.QuadPart = 0;
		status = _r_sys_openprocess (
			&hprocess,
			parent_pid,
			PROCESS_QUERY_LIMITED_INFORMATION
		);

		if (NT_SUCCESS (status))
		{
			if (
				GetProcessTimes (
					hprocess,
					&parent_creation_filetime,
					&exit_filetime,
					&kernel_filetime,
					&user_filetime
				)
			)
			{
				opened_parent_creation.LowPart = parent_creation_filetime.dwLowDateTime;
				opened_parent_creation.HighPart = parent_creation_filetime.dwHighDateTime;

				if (opened_parent_creation.QuadPart == parent_process->CreateTime.QuadPart)
				{
					status = _r_sys_queryprocessstring (
						&process_path,
						hprocess,
						ProcessImageFileNameWin32
					);
				}
			}

			NtClose (hprocess);
		}

		if (string_builder.string->length)
			_r_obj_appendstringbuilder (&string_builder, L" <- ");

		_r_obj_appendstringbuilderformat (
			&string_builder,
			L"%s (%" TEXT (PR_ULONG) L")",
			_r_obj_getstringordefault (process_path, L"<unavailable>"),
			parent_pid
		);

		if (
			!NT_SUCCESS (status) ||
			opened_parent_creation.QuadPart != parent_process->CreateTime.QuadPart
		)
		{
			_r_obj_appendstringbuilder (&string_builder, L" <parent PID reused or unavailable>");

			if (process_path)
				_r_obj_dereference (process_path);

			break;
		}

		if (process_path)
			_r_obj_dereference (process_path);

		current_pid = parent_pid;
		current_creation = parent_process->CreateTime;
	}

	_r_mem_free (process_list);

	return _r_obj_finalstringbuilder (&string_builder);
}

static BOOLEAN _app_codex_getprocessidentity (
	_In_ PITEM_LOG ptr_log,
	_Out_ PCODEX_PROCESS_IDENTITY identity
)
{
	PTOKEN_USER token_user = NULL;
	PR_STRING process_path = NULL;
	PR_STRING process_sid = NULL;
	HANDLE hprocess = NULL;
	HANDLE htoken = NULL;
	FILETIME creation_filetime;
	FILETIME exit_filetime;
	FILETIME kernel_filetime;
	FILETIME user_filetime;
	BOOLEAN is_valid = FALSE;
	NTSTATUS status;

	RtlSecureZeroMemory (identity, sizeof (CODEX_PROCESS_IDENTITY));

	if (_r_obj_isstringempty (ptr_log->path) || _r_obj_isstringempty (ptr_log->user_sid))
		return FALSE;

	identity->process_id = _app_codex_resolvepid (ptr_log, &identity->is_ambiguous);

	if (!identity->process_id || identity->is_ambiguous)
		return FALSE;

	status = _r_sys_openprocess (
		&hprocess,
		identity->process_id,
		PROCESS_QUERY_LIMITED_INFORMATION
	);

	if (!NT_SUCCESS (status))
		goto CleanupExit;

	status = _r_sys_queryprocessstring (
		&process_path,
		hprocess,
		ProcessImageFileNameWin32
	);

	if (
		!NT_SUCCESS (status) ||
		_r_obj_isstringempty (process_path) ||
		!_r_str_isequal (&process_path->sr, &ptr_log->path->sr, TRUE)
	)
	{
		goto CleanupExit;
	}

	if (!GetProcessTimes (
		hprocess,
		&creation_filetime,
		&exit_filetime,
		&kernel_filetime,
		&user_filetime
	))
	{
		goto CleanupExit;
	}

	identity->creation_time = _r_unixtime_from_filetime (&creation_filetime);
	identity->creation_filetime = creation_filetime;

	// Reject a reused PID whose process started after the WFP event.
	if (identity->creation_time > ptr_log->timestamp + 1)
		goto CleanupExit;

	status = NtOpenProcessTokenEx (hprocess, TOKEN_QUERY, 0, &htoken);

	if (!NT_SUCCESS (status))
		goto CleanupExit;

	status = _r_sys_querytokeninformation (
		(PVOID_PTR)&token_user,
		htoken,
		TokenUser
	);

	NtClose (htoken);
	htoken = NULL;

	if (!NT_SUCCESS (status) || !token_user)
		goto CleanupExit;

	status = _r_str_fromsid (&process_sid, token_user->User.Sid);

	if (
		!NT_SUCCESS (status) ||
		!_r_str_isequal (&process_sid->sr, &ptr_log->user_sid->sr, TRUE)
	)
	{
		goto CleanupExit;
	}

	identity->process_path = process_path;
	process_path = NULL;
	is_valid = TRUE;

CleanupExit:

	if (token_user)
		_r_mem_free (token_user);

	if (process_sid)
		_r_obj_dereference (process_sid);

	if (process_path)
		_r_obj_dereference (process_path);

	if (htoken)
		NtClose (htoken);

	if (hprocess)
		NtClose (hprocess);

	if (!is_valid)
	{
		identity->process_id = 0;
		identity->creation_time = 0;
	}

	return is_valid;
}

static VOID _app_codex_enrichprocessidentity (
	_Inout_ PCODEX_PROCESS_IDENTITY identity
)
{
	PR_STRING process_path = NULL;
	PR_STRING raw_command_line = NULL;
	HANDLE hprocess = NULL;
	FILETIME creation_filetime;
	FILETIME exit_filetime;
	FILETIME kernel_filetime;
	FILETIME user_filetime;
	LARGE_INTEGER expected_creation;
	LARGE_INTEGER opened_creation;
	NTSTATUS status;

	status = _r_sys_openprocess (
		&hprocess,
		identity->process_id,
		PROCESS_QUERY_LIMITED_INFORMATION
	);

	if (!NT_SUCCESS (status))
		goto CleanupExit;

	status = _r_sys_queryprocessstring (
		&process_path,
		hprocess,
		ProcessImageFileNameWin32
	);

	if (
		!NT_SUCCESS (status) ||
		_r_obj_isstringempty (process_path) ||
		!_r_str_isequal (&process_path->sr, &identity->process_path->sr, TRUE) ||
		!GetProcessTimes (
			hprocess,
			&creation_filetime,
			&exit_filetime,
			&kernel_filetime,
			&user_filetime
		)
	)
	{
		goto CleanupExit;
	}

	expected_creation.LowPart = identity->creation_filetime.dwLowDateTime;
	expected_creation.HighPart = identity->creation_filetime.dwHighDateTime;
	opened_creation.LowPart = creation_filetime.dwLowDateTime;
	opened_creation.HighPart = creation_filetime.dwHighDateTime;

	if (opened_creation.QuadPart != expected_creation.QuadPart)
		goto CleanupExit;

	identity->parent_chain = _app_codex_getparentchain (
		identity->process_id,
		identity->creation_filetime
	);

	_r_sys_queryprocessstring (
		&raw_command_line,
		hprocess,
		ProcessCommandLineInformation
	);

	identity->command_line = _app_codex_sanitizecommandline (
		raw_command_line,
		identity->process_path
	);

CleanupExit:

	if (process_path)
		_r_obj_dereference (process_path);

	if (raw_command_line)
		_r_obj_dereference (raw_command_line);

	if (hprocess)
		NtClose (hprocess);
}

static PR_STRING _app_codex_getcanonicalpath (
	_In_ HANDLE hfile
)
{
	PR_STRING path;
	ULONG capacity;
	ULONG length;

	length = GetFinalPathNameByHandleW (
		hfile,
		NULL,
		0,
		FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	);

	if (!length)
		return NULL;

	capacity = length + 1;
	path = _r_obj_createstring_ex (NULL, capacity * sizeof (WCHAR));

	length = GetFinalPathNameByHandleW (
		hfile,
		path->buffer,
		capacity,
		FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
	);

	if (!length || length >= capacity)
	{
		_r_obj_dereference (path);
		return NULL;
	}

	_r_str_trimtonullterminator (&path->sr);

	return path;
}

static BOOLEAN _app_codex_hasalternatestream (
	_In_ PR_STRING path
)
{
	ULONG_PTR allowed_colon;
	ULONG_PTR length;

	length = path->length / sizeof (WCHAR);
	allowed_colon = _r_str_isstartswith2 (&path->sr, L"\\\\?\\", TRUE) ? 5 : 1;

	for (ULONG_PTR i = 0; i < length; i++)
	{
		if (path->buffer[i] == L':' && i != allowed_colon)
			return TRUE;
	}

	return FALSE;
}

static PR_STRING _app_codex_matchsandboxroot (
	_In_opt_ PR_STRING canonical_path
)
{
	R_STRINGREF current;
	R_STRINGREF root_ref;
	R_STRINGREF remaining;
	PR_STRING canonical_root;
	PR_STRING configured_roots;
	PR_STRING root;
	HANDLE hroot;
	ULONG_PTR root_chars;
	NTSTATUS status;

	if (_r_obj_isstringempty (canonical_path) || _app_codex_hasalternatestream (canonical_path))
		return NULL;

	configured_roots = _r_config_getstringexpand (
		L"CodexSandboxRoots",
		L"",
		NULL
	);

	if (_r_obj_isstringempty (configured_roots))
	{
		if (configured_roots)
			_r_obj_dereference (configured_roots);

		return NULL;
	}

	current = configured_roots->sr;

	while (current.length)
	{
		if (_r_str_splitatchar (&current, L';', &root_ref, &remaining))
		{
			current = remaining;
		}
		else
		{
			root_ref = current;
			current.length = 0;
		}

		while (root_ref.length && (root_ref.buffer[0] == L' ' || root_ref.buffer[0] == L'\t'))
			_r_str_skiplength (&root_ref, sizeof (WCHAR));

		while (
			root_ref.length &&
			(root_ref.buffer[(root_ref.length / sizeof (WCHAR)) - 1] == L' ' ||
			 root_ref.buffer[(root_ref.length / sizeof (WCHAR)) - 1] == L'\t')
		)
		{
			root_ref.length -= sizeof (WCHAR);
		}

		if (!root_ref.length)
			continue;

		root = _r_obj_createstring2 (&root_ref);
		status = _r_fs_openfile (
			&hroot,
			&root->sr,
			FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			0,
			TRUE
		);

		_r_obj_dereference (root);

		if (!NT_SUCCESS (status))
			continue;

		canonical_root = _app_codex_getcanonicalpath (hroot);
		NtClose (hroot);

		if (!canonical_root || _app_codex_hasalternatestream (canonical_root))
		{
			if (canonical_root)
				_r_obj_dereference (canonical_root);

			continue;
		}

		while (
			canonical_root->sr.length > sizeof (WCHAR) &&
			canonical_root->buffer[(canonical_root->sr.length / sizeof (WCHAR)) - 1] == L'\\'
		)
		{
			canonical_root->sr.length -= sizeof (WCHAR);
		}

		root_chars = canonical_root->sr.length / sizeof (WCHAR);

		if (
			_r_str_isstartswith (&canonical_path->sr, &canonical_root->sr, TRUE) &&
			(canonical_path->sr.length == canonical_root->sr.length ||
			 canonical_path->buffer[root_chars] == L'\\')
		)
		{
			_r_obj_dereference (configured_roots);
			return canonical_root;
		}

		_r_obj_dereference (canonical_root);
	}

	_r_obj_dereference (configured_roots);

	return NULL;
}

static VOID _app_codex_getsignature (
	_In_ HANDLE hfile,
	_In_ PR_STRING path,
	_Out_ PLONG trust_status,
	_Out_ PR_STRING_PTR signer
)
{
	GUID action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_FILE_INFO file_info = {0};

	file_info.cbStruct = sizeof (WINTRUST_FILE_INFO);
	file_info.pcwszFilePath = path->buffer;
	file_info.hFile = hfile;

	*signer = NULL;
	*trust_status = _app_verifyfromfile (
		WTD_CHOICE_FILE,
		&file_info,
		&action_id,
		NULL,
		signer
	);

	if (*trust_status == TRUST_E_NOSIGNATURE)
	{
		*trust_status = _app_verifyfilefromcatalog (
			hfile,
			path->buffer,
			BCRYPT_SHA256_ALGORITHM,
			signer
		);

		if (*trust_status == ERROR_SUCCESS && !*signer)
			*trust_status = TRUST_E_NOSIGNATURE;
	}
}

static VOID _app_codex_writeaudit (
	_In_ PR_STRING buffer
)
{
	PR_STRING audit_path;
	HANDLE hfile;
	LONG64 file_size;
	NTSTATUS status;

	if (_r_obj_isstringempty (buffer))
		return;

	audit_path = _r_config_getstringexpand (
		L"CodexDiagnosticLogPath",
		CODEX_AUDIT_PATH_DEFAULT,
		NULL
	);

	if (!audit_path)
		return;

	status = _r_fs_createfile (
		&hfile,
		&audit_path->sr,
		FILE_OPEN_IF,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FALSE,
		NULL
	);

	if (NT_SUCCESS (status))
	{
		_r_fs_getsize (NULL, hfile, &file_size);

		if (file_size == 0)
		{
			const BYTE bom[] = {0xFF, 0xFE};
			_r_fs_writefile (hfile, (PVOID)bom, sizeof (bom));
		}
		else
		{
			_r_fs_setpos (hfile, file_size);
		}

		_r_fs_writefile (hfile, buffer->buffer, (ULONG)buffer->length);
		NtClose (hfile);
	}

	_r_obj_dereference (audit_path);
}

VOID _app_codex_auditblocked (
	_In_ PITEM_LOG ptr_log
)
{
	CODEX_PROCESS_IDENTITY identity = {0};
	PR_STRING canonical_path = NULL;
	PR_STRING creation_string = NULL;
	PR_STRING date_string = NULL;
	PR_STRING hash = NULL;
	PR_STRING matched_root = NULL;
	PR_STRING pid_string = NULL;
	PR_STRING signer = NULL;
	PR_STRING buffer = NULL;
	HANDLE hfile = NULL;
	LONG trust_status = TRUST_E_NOSIGNATURE;
	BOOLEAN is_correlated;
	BOOLEAN is_sid_match;
	NTSTATUS status;

	if (!_r_config_getboolean (L"IsCodexDiagnosticEnabled", FALSE, NULL))
		return;

	if (ptr_log->is_allow || !ptr_log->is_myprovider || ptr_log->direction != FWP_DIRECTION_OUTBOUND)
		return;

	is_sid_match = _app_codex_stringlistcontains (
		L"CodexDiagnosticSids",
		ptr_log->user_sid
	);
	is_correlated = _app_codex_getprocessidentity (ptr_log, &identity);

	if (is_correlated)
	{
		pid_string = _r_format_string (
			L"%" TEXT (PR_ULONG),
			identity.process_id
		);
		creation_string = _r_format_unixtime (
			identity.creation_time,
			FDTF_SHORTDATE | FDTF_LONGTIME
		);

		status = _r_fs_openfile (
			&hfile,
			&identity.process_path->sr,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			0,
			FALSE
		);

		if (NT_SUCCESS (status))
		{
			canonical_path = _app_codex_getcanonicalpath (hfile);
			matched_root = _app_codex_matchsandboxroot (canonical_path);
		}
	}

	// A configured SID or an approved canonical root must associate the event with Codex.
	// With neither configured, diagnostic mode remains inert even when enabled.
	if (!is_sid_match && !matched_root)
		goto CleanupExit;

	if (is_correlated)
		_app_codex_enrichprocessidentity (&identity);

	// File evidence is collected only from the image path of a validated live process.
	// It describes the on-disk file at audit time; WFP does not bind the event to this handle.
	if (is_correlated && hfile)
	{
		_r_crypt_getfilehash (&hash, BCRYPT_SHA256_ALGORITHM, NULL, hfile);
		_app_codex_getsignature (
			hfile,
			identity.process_path,
			&trust_status,
			&signer
		);
	}

	date_string = _r_format_unixtime (
		ptr_log->timestamp,
		FDTF_SHORTDATE | FDTF_LONGTIME
	);

	buffer = _r_format_string (
		L"\r\n[Codex Diagnostic]\r\n"
		L"Action: Observed blocked outbound event (no permit created)\r\n"
		L"Timestamp: %s\r\n"
		L"Executable reported by WFP: %s\r\n"
		L"Validated live process path: %s\r\n"
		L"Canonical on-disk path at audit time: %s\r\n"
		L"Evidence binding: %s\r\n"
		L"PID: %s\r\n"
		L"PID correlation: %s\r\n"
		L"Parent chain: %s\r\n"
		L"Command line: %s\r\n"
		L"Process creation time: %s\r\n"
		L"Username: %s\r\n"
		L"User SID: %s\r\n"
		L"Codex SID association: %s\r\n"
		L"Signer of on-disk file at audit time: %s\r\n"
		L"Certificate status of on-disk file: 0x%08X\r\n"
		L"SHA-256 of on-disk file at audit time: %s\r\n"
		L"WFP event type: %" TEXT (PR_ULONG) L"\r\n"
		L"WFP layer: %s\r\n"
		L"WFP filter: %s\r\n"
		L"WFP filter ID: %" TEXT (PRIu64) L"\r\n"
		L"Protocol: %s (%" TEXT (PRIu8) L")\r\n"
		L"Local endpoint: %s:%" TEXT (PRIu16) L"\r\n"
		L"Remote endpoint: %s:%" TEXT (PRIu16) L"\r\n"
		L"Inside approved sandbox root: %s\r\n",
		_r_obj_getstringordefault (date_string, L"<unknown>"),
		_r_obj_getstringordefault (ptr_log->path, L"<unknown>"),
		_r_obj_getstringordefault (identity.process_path, L"<unavailable>"),
		_r_obj_getstringordefault (canonical_path, L"<unavailable>"),
		is_correlated ? L"validated live path; file metadata is not kernel-bound to the WFP event" : L"no executable file evidence collected",
		_r_obj_getstringordefault (pid_string, L"<unavailable>"),
		is_correlated ? L"exact network tuple + path + SID + creation-time validation" : (identity.is_ambiguous ? L"ambiguous; no PID selected" : L"no validated live process match"),
		_r_obj_getstringordefault (identity.parent_chain, L"<unavailable>"),
		_r_obj_getstringordefault (identity.command_line, L"<unavailable>"),
		_r_obj_getstringordefault (creation_string, L"<unavailable>"),
		_r_obj_getstringordefault (ptr_log->username, L"<unknown>"),
		_r_obj_getstringordefault (ptr_log->user_sid, L"<unknown>"),
		is_sid_match ? L"matched configured CodexDiagnosticSids" : L"not matched; event associated by approved canonical root",
		_r_obj_getstringordefault (signer, L"<unsigned or unavailable>"),
		trust_status,
		_r_obj_getstringordefault (hash, L"<unavailable>"),
		ptr_log->event_type,
		_r_obj_getstringordefault (ptr_log->layer_name, L"<unknown>"),
		_r_obj_getstringordefault (ptr_log->filter_name, L"<unknown>"),
		ptr_log->filter_id,
		_r_obj_getstringordefault (ptr_log->protocol_str, L"<unknown>"),
		ptr_log->protocol,
		_r_obj_getstringordefault (ptr_log->local_addr_str, L"<unknown>"),
		ptr_log->local_port,
		_r_obj_getstringordefault (ptr_log->remote_addr_str, L"<unknown>"),
		ptr_log->remote_port,
		_r_obj_getstringordefault (matched_root, L"<no validated root match>")
	);

	_app_codex_writeaudit (buffer);

CleanupExit:

	if (hfile)
		NtClose (hfile);

	if (canonical_path)
		_r_obj_dereference (canonical_path);

	if (creation_string)
		_r_obj_dereference (creation_string);

	if (date_string)
		_r_obj_dereference (date_string);

	if (hash)
		_r_obj_dereference (hash);

	if (matched_root)
		_r_obj_dereference (matched_root);

	if (pid_string)
		_r_obj_dereference (pid_string);

	if (signer)
		_r_obj_dereference (signer);

	if (buffer)
		_r_obj_dereference (buffer);

	_app_codex_deleteprocessidentity (&identity);
}
