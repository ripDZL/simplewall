// simplewall modified fork
// Diagnostic-only Codex sandbox identity capture.
// Copyright (c) 2026 simplewall fork contributors
//
// This module must not create, enable, or remove WFP permit filters.

#include "global.h"

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
	_In_ ULONG process_id
)
{
	R_STRINGBUILDER string_builder;
	PSYSTEM_PROCESS_INFORMATION process_list;
	PSYSTEM_PROCESS_INFORMATION process;
	PR_STRING process_path;
	HANDLE hprocess;
	ULONG current_pid = process_id;
	ULONG parent_pid;
	NTSTATUS status;

	status = _r_sys_enumprocesses (&process_list);

	if (!NT_SUCCESS (status))
		return NULL;

	_r_obj_initializestringbuilder (&string_builder, 256);

	for (ULONG depth = 0; depth < 8 && current_pid; depth++)
	{
		process = PR_FIRST_PROCESS (process_list);
		parent_pid = 0;

		while (process)
		{
			if (HandleToULong (process->UniqueProcessId) == current_pid)
			{
				parent_pid = HandleToULong (process->InheritedFromUniqueProcessId);
				break;
			}

			process = PR_NEXT_PROCESS (process);
		}

		if (!process || !parent_pid || parent_pid == current_pid)
			break;

		process_path = NULL;
		status = _r_sys_openprocess (
			&hprocess,
			parent_pid,
			PROCESS_QUERY_LIMITED_INFORMATION
		);

		if (NT_SUCCESS (status))
		{
			_r_sys_queryprocessstring (
				&process_path,
				hprocess,
				ProcessImageFileNameWin32
			);

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

		if (process_path)
			_r_obj_dereference (process_path);

		current_pid = parent_pid;
	}

	_r_mem_free (process_list);

	return _r_obj_finalstringbuilder (&string_builder);
}

static BOOLEAN _app_codex_getprocessidentity (
	_In_ PITEM_LOG ptr_log,
	_Out_ PULONG process_id,
	_Out_ PLONG64 creation_time,
	_Out_ PR_STRING_PTR parent_chain,
	_Out_ PR_STRING_PTR command_line,
	_Out_ PBOOLEAN is_ambiguous
)
{
	PTOKEN_USER token_user = NULL;
	PR_STRING raw_command_line = NULL;
	PR_STRING process_path = NULL;
	PR_STRING process_sid = NULL;
	LPWSTR *arguments;
	HANDLE hprocess;
	HANDLE htoken;
	FILETIME creation_filetime;
	FILETIME exit_filetime;
	FILETIME kernel_filetime;
	FILETIME user_filetime;
	INT argument_count = 0;
	NTSTATUS status;

	*process_id = _app_codex_resolvepid (ptr_log, is_ambiguous);
	*creation_time = 0;
	*parent_chain = NULL;
	*command_line = NULL;

	if (!*process_id || *is_ambiguous)
		return FALSE;

	status = _r_sys_openprocess (
		&hprocess,
		*process_id,
		PROCESS_QUERY_LIMITED_INFORMATION
	);

	if (!NT_SUCCESS (status))
		return FALSE;

	status = _r_sys_queryprocessstring (
		&process_path,
		hprocess,
		ProcessImageFileNameWin32
	);

	if (
		!NT_SUCCESS (status) ||
		_r_obj_isstringempty (process_path) ||
		_r_obj_isstringempty (ptr_log->path) ||
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

	*creation_time = _r_unixtime_from_filetime (&creation_filetime);

	// Reject a reused PID whose process started after the WFP event.
	if (*creation_time > ptr_log->timestamp + 1)
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

	if (!NT_SUCCESS (status) || !token_user)
		goto CleanupExit;

	status = _r_str_fromsid (&process_sid, token_user->User.Sid);

	if (
		!NT_SUCCESS (status) ||
		_r_obj_isstringempty (ptr_log->user_sid) ||
		!_r_str_isequal (&process_sid->sr, &ptr_log->user_sid->sr, TRUE)
	)
	{
		goto CleanupExit;
	}

	*parent_chain = _app_codex_getparentchain (*process_id);

	_r_sys_queryprocessstring (
		&raw_command_line,
		hprocess,
		ProcessCommandLineInformation
	);

	arguments = raw_command_line ? CommandLineToArgvW (raw_command_line->buffer, &argument_count) : NULL;

	*command_line = _r_format_string (
		L"%s <%d argument value(s) redacted>",
		process_path->buffer,
		max (argument_count - 1, 0)
	);

	if (arguments)
		LocalFree (arguments);

	if (token_user)
		_r_mem_free (token_user);

	if (raw_command_line)
		_r_obj_dereference (raw_command_line);

	if (process_sid)
		_r_obj_dereference (process_sid);

	_r_obj_dereference (process_path);
	NtClose (hprocess);

	return TRUE;

CleanupExit:

	if (token_user)
		_r_mem_free (token_user);

	if (raw_command_line)
		_r_obj_dereference (raw_command_line);

	if (process_sid)
		_r_obj_dereference (process_sid);

	if (process_path)
		_r_obj_dereference (process_path);

	NtClose (hprocess);

	*process_id = 0;
	*creation_time = 0;

	return FALSE;
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
	PR_STRING canonical_path = NULL;
	PR_STRING command_line = NULL;
	PR_STRING creation_string = NULL;
	PR_STRING date_string;
	PR_STRING hash = NULL;
	PR_STRING matched_root = NULL;
	PR_STRING parent_chain = NULL;
	PR_STRING pid_string = NULL;
	PR_STRING signer = NULL;
	PR_STRING buffer;
	HANDLE hfile = NULL;
	LONG64 creation_time = 0;
	LONG trust_status = TRUST_E_NOSIGNATURE;
	ULONG process_id = 0;
	BOOLEAN is_ambiguous = FALSE;
	BOOLEAN is_correlated;
	NTSTATUS status;

	if (!_r_config_getboolean (L"IsCodexDiagnosticEnabled", FALSE, NULL))
		return;

	if (ptr_log->is_allow || !ptr_log->is_myprovider || ptr_log->direction != FWP_DIRECTION_OUTBOUND)
		return;

	is_correlated = _app_codex_getprocessidentity (
		ptr_log,
		&process_id,
		&creation_time,
		&parent_chain,
		&command_line,
		&is_ambiguous
	);

	if (is_correlated)
	{
		pid_string = _r_format_string (L"%" TEXT (PR_ULONG), process_id);
		creation_string = _r_format_unixtime (
			creation_time,
			FDTF_SHORTDATE | FDTF_LONGTIME
		);
	}

	if (!_r_obj_isstringempty (ptr_log->path))
	{
		status = _r_fs_openfile (
			&hfile,
			&ptr_log->path->sr,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			0,
			FALSE
		);

		if (NT_SUCCESS (status))
		{
			canonical_path = _app_codex_getcanonicalpath (hfile);
			matched_root = _app_codex_matchsandboxroot (canonical_path);
			_r_crypt_getfilehash (&hash, BCRYPT_SHA256_ALGORITHM, NULL, hfile);
			_app_codex_getsignature (hfile, ptr_log->path, &trust_status, &signer);
		}
	}

	date_string = _r_format_unixtime (
		ptr_log->timestamp,
		FDTF_SHORTDATE | FDTF_LONGTIME
	);

	buffer = _r_format_string (
		L"\r\n[Codex Diagnostic]\r\n"
		L"Action: Observed blocked outbound event (no permit created)\r\n"
		L"Timestamp: %s\r\n"
		L"Executable: %s\r\n"
		L"Canonical executable: %s\r\n"
		L"PID: %s\r\n"
		L"PID correlation: %s\r\n"
		L"Parent chain: %s\r\n"
		L"Command line: %s\r\n"
		L"Process creation time: %s\r\n"
		L"Username: %s\r\n"
		L"User SID: %s\r\n"
		L"Signer: %s\r\n"
		L"Certificate status: 0x%08X\r\n"
		L"SHA-256: %s\r\n"
		L"WFP layer: %s\r\n"
		L"WFP filter: %s\r\n"
		L"WFP filter ID: %" TEXT (PRIu64) L"\r\n"
		L"Protocol: %s (%" TEXT (PRIu8) L")\r\n"
		L"Local endpoint: %s:%" TEXT (PRIu16) L"\r\n"
		L"Remote endpoint: %s:%" TEXT (PRIu16) L"\r\n"
		L"Inside approved sandbox root: %s\r\n",
		_r_obj_getstringordefault (date_string, L"<unknown>"),
		_r_obj_getstringordefault (ptr_log->path, L"<unknown>"),
		_r_obj_getstringordefault (canonical_path, L"<unavailable>"),
		_r_obj_getstringordefault (pid_string, L"<unavailable>"),
		is_correlated ? L"exact network tuple + path + SID + creation-time validation" : (is_ambiguous ? L"ambiguous; no PID selected" : L"no validated live process match"),
		_r_obj_getstringordefault (parent_chain, L"<unavailable>"),
		_r_obj_getstringordefault (command_line, L"<unavailable>"),
		_r_obj_getstringordefault (creation_string, L"<unavailable>"),
		_r_obj_getstringordefault (ptr_log->username, L"<unknown>"),
		_r_obj_getstringordefault (ptr_log->user_sid, L"<unknown>"),
		_r_obj_getstringordefault (signer, L"<unsigned or unavailable>"),
		trust_status,
		_r_obj_getstringordefault (hash, L"<unavailable>"),
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

	if (hfile)
		NtClose (hfile);

	if (canonical_path)
		_r_obj_dereference (canonical_path);

	if (command_line)
		_r_obj_dereference (command_line);

	if (creation_string)
		_r_obj_dereference (creation_string);

	if (date_string)
		_r_obj_dereference (date_string);

	if (hash)
		_r_obj_dereference (hash);

	if (matched_root)
		_r_obj_dereference (matched_root);

	if (parent_chain)
		_r_obj_dereference (parent_chain);

	if (pid_string)
		_r_obj_dereference (pid_string);

	if (signer)
		_r_obj_dereference (signer);

	_r_obj_dereference (buffer);
}
