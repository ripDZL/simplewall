// simplewall
// Copyright (c) 2019-2026 Henry++

#include "global.h"

#define NETWORK_DIAGNOSTIC_PATH_DEFAULT L"%USERPROFILE%\\simplewall-network-diagnostic.log"
#define NETWORK_DIAGNOSTIC_STATUS_NOT_CALLED ((ULONG)0xFFFFFFFF)

typedef struct _ITEM_NETWORK_DIAGNOSTIC_STAGE
{
	ULONG first_status;
	ULONG second_status;
	ULONG required_size;
	ULONG entries_count;
	ULONG existing_count;
	ULONG added_count;
	ULONG path_fail_count;
} ITEM_NETWORK_DIAGNOSTIC_STAGE, *PITEM_NETWORK_DIAGNOSTIC_STAGE;

static BOOLEAN _app_network_isdiagnosticenabled ()
{
	return _r_config_getboolean (L"IsNetworkDiagnosticEnabled", FALSE, NULL);
}

static VOID _app_network_writediagnostic (
	_In_ _Printf_format_string_ LPCWSTR format,
	...
)
{
	PR_STRING diagnostic_path;
	PR_STRING buffer;
	HANDLE hfile;
	LONG64 file_size;
	NTSTATUS status;
	va_list arg_ptr;

	if (!_app_network_isdiagnosticenabled ())
		return;

	va_start (arg_ptr, format);
	buffer = _r_format_string_v (format, arg_ptr);
	va_end (arg_ptr);

	if (_r_obj_isstringempty (buffer))
	{
		if (buffer)
			_r_obj_dereference (buffer);

		return;
	}

	diagnostic_path = _r_config_getstringexpand (
		L"NetworkDiagnosticLogPath",
		NETWORK_DIAGNOSTIC_PATH_DEFAULT,
		NULL
	);

	if (!diagnostic_path)
	{
		_r_obj_dereference (buffer);

		return;
	}

	status = _r_fs_createfile (
		&hfile,
		&diagnostic_path->sr,
		FILE_OPEN_IF,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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

	_r_obj_dereference (diagnostic_path);
	_r_obj_dereference (buffer);
}

static VOID _app_network_update_stats_values (
	_Inout_ PITEM_NETWORK ptr_network,
	_In_ ULONG64 bytes_in,
	_In_ ULONG64 bytes_out
)
{
	ULONG64 bytes_delta, current_tick, elapsed;

	current_tick = _r_sys_gettickcount64 ();

	if (!ptr_network->is_stats_initialized)
	{
		ptr_network->last_bytes_in = bytes_in;
		ptr_network->last_bytes_out = bytes_out;
		ptr_network->last_stats_tick = current_tick;
		ptr_network->is_stats_initialized = TRUE;

		return;
	}

	elapsed = current_tick - ptr_network->last_stats_tick;

	if (!elapsed)
		return;

	bytes_delta = bytes_in >= ptr_network->last_bytes_in ? bytes_in - ptr_network->last_bytes_in : 0;

	_InterlockedExchangeAdd64 (&ptr_network->download_total, bytes_delta);
	_InterlockedExchange64 (&ptr_network->download_speed, (bytes_delta * 1000) / elapsed);

	bytes_delta = bytes_out >= ptr_network->last_bytes_out ? bytes_out - ptr_network->last_bytes_out : 0;

	_InterlockedExchangeAdd64 (&ptr_network->upload_total, bytes_delta);
	_InterlockedExchange64 (&ptr_network->upload_speed, (bytes_delta * 1000) / elapsed);

	ptr_network->last_bytes_in = bytes_in;
	ptr_network->last_bytes_out = bytes_out;
	ptr_network->last_stats_tick = current_tick;
}

static VOID _app_network_update_tcp4_stats (
	_Inout_ PITEM_NETWORK ptr_network,
	_In_ PMIB_TCPROW_OWNER_MODULE row
)
{
	TCP_ESTATS_DATA_ROD_v0 data_rod = {0};
	TCP_ESTATS_DATA_RW_v0 data_rw = {0};
	MIB_TCPROW tcp_row = {0};
	ULONG status;

	tcp_row.dwState = row->dwState;
	tcp_row.dwLocalAddr = row->dwLocalAddr;
	tcp_row.dwLocalPort = row->dwLocalPort;
	tcp_row.dwRemoteAddr = row->dwRemoteAddr;
	tcp_row.dwRemotePort = row->dwRemotePort;

	if (!ptr_network->is_stats_enabled)
	{
		data_rw.EnableCollection = TRUE;

		status = SetPerTcpConnectionEStats (&tcp_row, TcpConnectionEstatsData, (PUCHAR)&data_rw, 0, sizeof (TCP_ESTATS_DATA_RW_v0), 0);

		if (status != NO_ERROR)
			return;

		ptr_network->is_stats_enabled = TRUE;
	}

	status = GetPerTcpConnectionEStats (&tcp_row, TcpConnectionEstatsData, (PUCHAR)&data_rw, 0, sizeof (data_rw), NULL, 0, 0, (PUCHAR)&data_rod, 0, sizeof (TCP_ESTATS_DATA_ROD_v0));

	if (status == NO_ERROR && data_rw.EnableCollection)
		_app_network_update_stats_values (ptr_network, data_rod.DataBytesIn, data_rod.DataBytesOut);
}

static VOID _app_network_update_tcp6_stats (
	_Inout_ PITEM_NETWORK ptr_network,
	_In_ PMIB_TCP6ROW_OWNER_MODULE row
)
{
	TCP_ESTATS_DATA_ROD_v0 data_rod = {0};
	TCP_ESTATS_DATA_RW_v0 data_rw = {0};
	MIB_TCP6ROW tcp_row = {0};
	ULONG status;

	RtlCopyMemory (&tcp_row.LocalAddr, row->ucLocalAddr, sizeof (IN6_ADDR));
	tcp_row.dwLocalScopeId = row->dwLocalScopeId;
	tcp_row.dwLocalPort = row->dwLocalPort;
	RtlCopyMemory (&tcp_row.RemoteAddr, row->ucRemoteAddr, sizeof (IN6_ADDR));
	tcp_row.dwRemoteScopeId = row->dwRemoteScopeId;
	tcp_row.dwRemotePort = row->dwRemotePort;
	tcp_row.State = row->dwState;

	if (!ptr_network->is_stats_enabled)
	{
		data_rw.EnableCollection = TRUE;

		status = SetPerTcp6ConnectionEStats (&tcp_row, TcpConnectionEstatsData, (PUCHAR)&data_rw, 0, sizeof (TCP_ESTATS_DATA_RW_v0), 0);

		if (status != NO_ERROR)
			return;

		ptr_network->is_stats_enabled = TRUE;
	}

	status = GetPerTcp6ConnectionEStats (&tcp_row, TcpConnectionEstatsData, (PUCHAR)&data_rw, 0, sizeof (TCP_ESTATS_DATA_RW_v0), NULL, 0, 0, (PUCHAR)&data_rod, 0, sizeof (TCP_ESTATS_DATA_ROD_v0));

	if (status == NO_ERROR && data_rw.EnableCollection)
		_app_network_update_stats_values (ptr_network, data_rod.DataBytesIn, data_rod.DataBytesOut);
}

_Ret_maybenull_
PITEM_NETWORK_CONTEXT _app_network_getcontext ()
{
	static R_INITONCE init_once = PR_INITONCE_INIT;
	static PITEM_NETWORK_CONTEXT network_context = NULL;

	if (_r_initonce_begin (&init_once))
	{
		network_context = (PITEM_NETWORK_CONTEXT)_r_mem_allocate (sizeof (ITEM_NETWORK_CONTEXT));

		network_context->network_ptr = _r_obj_createhashtablepointer (0x100);
		network_context->checker_ptr = _r_obj_createhashtablepointer (0x100);

		_r_initonce_end (&init_once);
	}

	return network_context;
}

VOID _app_network_initialize (
	_In_ HWND hwnd
)
{
	PITEM_NETWORK_CONTEXT network_context;
	R_ENVIRONMENT environment;
	NTSTATUS status;

	if (!_r_config_getboolean (L"IsNetworkMonitorEnabled", TRUE, NULL))
	{
		_app_network_writediagnostic (L"[DEBUG-netmon] initialize monitor_enabled=0 hwnd=0x%p\r\n", hwnd);

		return;
	}

	network_context = _app_network_getcontext ();

	if (!network_context)
	{
		_app_network_writediagnostic (L"[DEBUG-netmon] initialize context_status=null hwnd=0x%p\r\n", hwnd);

		return;
	}

	network_context->hwnd = hwnd;

	_r_queuedlock_acquireexclusive (&network_context->lock_network);
	_r_obj_clearhashtable (network_context->network_ptr);
	_r_queuedlock_releaseexclusive (&network_context->lock_network);

	_r_queuedlock_acquireexclusive (&network_context->lock_checker);
	_r_obj_clearhashtable (network_context->checker_ptr);
	_r_queuedlock_releaseexclusive (&network_context->lock_checker);

	// create network monitor thread
	_r_sys_setenvironment (&environment, THREAD_PRIORITY_ABOVE_NORMAL, IoPriorityNormal, MEMORY_PRIORITY_NORMAL);

	status = _r_sys_createthread (NULL, NtCurrentProcess (), &_app_network_threadproc, network_context, &environment, L"NetworkMonitor");

	_app_network_writediagnostic (L"[DEBUG-netmon] initialize monitor_enabled=1 hwnd=0x%p context=0x%p create_status=0x%08X\r\n", hwnd, network_context, (ULONG)status);
}

VOID _app_network_uninitialize (
	_In_ PITEM_NETWORK_CONTEXT context
)
{
	_r_queuedlock_acquireexclusive (&context->lock_network);
	_r_obj_clearhashtable (context->network_ptr);
	_r_queuedlock_releaseexclusive (&context->lock_network);

	_r_queuedlock_acquireexclusive (&context->lock_checker);
	_r_obj_clearhashtable (context->checker_ptr);
	_r_queuedlock_releaseexclusive (&context->lock_checker);
}

VOID _app_network_generatetable (
	_Inout_ PITEM_NETWORK_CONTEXT network_context
)
{
	static volatile LONG diagnostic_cycle = 0;

	ITEM_NETWORK_DIAGNOSTIC_STAGE tcp4_diag = {0};
	ITEM_NETWORK_DIAGNOSTIC_STAGE tcp6_diag = {0};
	ITEM_NETWORK_DIAGNOSTIC_STAGE udp4_diag = {0};
	ITEM_NETWORK_DIAGNOSTIC_STAGE udp6_diag = {0};
	PMIB_TCP6TABLE_OWNER_MODULE tcp6_table;
	PMIB_UDP6TABLE_OWNER_MODULE udp6_table;
	PMIB_TCPTABLE_OWNER_MODULE tcp4_table;
	PMIB_UDPTABLE_OWNER_MODULE udp4_table;
	PITEM_NETWORK ptr_network;
	IN_ADDR local_addr, remote_addr;
	PVOID buffer;
	ULONG allocated_size, network_hash, required_size = 0;
	ULONG status;
	LONG cycle_id = 0;
	BOOLEAN is_diagnostic;

	is_diagnostic = _app_network_isdiagnosticenabled ();

	if (is_diagnostic)
	{
		cycle_id = _InterlockedIncrement (&diagnostic_cycle);

		tcp4_diag.second_status = NETWORK_DIAGNOSTIC_STATUS_NOT_CALLED;
		tcp6_diag.second_status = NETWORK_DIAGNOSTIC_STATUS_NOT_CALLED;
		udp4_diag.second_status = NETWORK_DIAGNOSTIC_STATUS_NOT_CALLED;
		udp6_diag.second_status = NETWORK_DIAGNOSTIC_STATUS_NOT_CALLED;
	}

	_r_queuedlock_acquireexclusive (&network_context->lock_checker);
	_r_obj_clearhashtable (network_context->checker_ptr);
	_r_queuedlock_releaseexclusive (&network_context->lock_checker);

	// TCP IPv4
	status = GetExtendedTcpTable (NULL, &required_size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);

	if (is_diagnostic)
	{
		tcp4_diag.first_status = status;
		tcp4_diag.required_size = required_size;
	}

	allocated_size = required_size;
	buffer = _r_mem_allocate (allocated_size);

	if (required_size)
	{
		tcp4_table = (PMIB_TCPTABLE_OWNER_MODULE)buffer;
		status = GetExtendedTcpTable (tcp4_table, &required_size, FALSE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);

		if (is_diagnostic)
			tcp4_diag.second_status = status;

		if (status == NO_ERROR)
		{
			if (is_diagnostic)
				tcp4_diag.entries_count = tcp4_table->dwNumEntries;

			for (ULONG i = 0; i < tcp4_table->dwNumEntries; i++)
			{
				RtlZeroMemory (&remote_addr, sizeof (IN_ADDR));
				RtlZeroMemory (&local_addr, sizeof (IN_ADDR));

				remote_addr.S_un.S_addr = tcp4_table->table[i].dwRemoteAddr;
				local_addr.S_un.S_addr = tcp4_table->table[i].dwLocalAddr;

				network_hash = _app_network_gethash (
					AF_INET,
					tcp4_table->table[i].dwOwningPid,
					&remote_addr,
					tcp4_table->table[i].dwRemotePort,
					&local_addr,
					tcp4_table->table[i].dwLocalPort,
					IPPROTO_TCP,
					tcp4_table->table[i].dwState
				);

				ptr_network = _app_network_getitem (network_hash);

				if (ptr_network)
				{
					if (is_diagnostic)
						tcp4_diag.existing_count += 1;

					_app_network_update_tcp4_stats (ptr_network, &tcp4_table->table[i]);

					_r_queuedlock_acquireexclusive (&network_context->lock_checker);
					_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, NULL);
					_r_queuedlock_releaseexclusive (&network_context->lock_checker);

					_r_obj_dereference (ptr_network);

					continue;
				}

				ptr_network = (PITEM_NETWORK)_r_obj_allocate (sizeof (ITEM_NETWORK), &_app_dereferencenetwork);

				if (!_app_network_getpath (ptr_network, tcp4_table->table[i].dwOwningPid, tcp4_table->table[i].OwningModuleInfo))
				{
					if (is_diagnostic)
						tcp4_diag.path_fail_count += 1;

					_r_obj_dereference (ptr_network);
					continue;
				}

				ptr_network->af = AF_INET;
				ptr_network->protocol = IPPROTO_TCP;
				ptr_network->protocol_str = _r_obj_createstring (_app_db_getprotoname (ptr_network->protocol, ptr_network->af, L"<unknown protocol>"));

				ptr_network->remote_addr.S_un.S_addr = tcp4_table->table[i].dwRemoteAddr;
				ptr_network->remote_port = _r_byteswap_ushort ((USHORT)tcp4_table->table[i].dwRemotePort);
				ptr_network->local_addr.S_un.S_addr = tcp4_table->table[i].dwLocalAddr;
				ptr_network->local_port = _r_byteswap_ushort ((USHORT)tcp4_table->table[i].dwLocalPort);

				ptr_network->state = tcp4_table->table[i].dwState;

				_app_network_update_tcp4_stats (ptr_network, &tcp4_table->table[i]);

				if (tcp4_table->table[i].dwState == MIB_TCP_STATE_ESTAB)
				{
					if (_app_network_isvalidconnection (ptr_network->af, &ptr_network->remote_addr) || _app_network_isvalidconnection (ptr_network->af, &ptr_network->local_addr))
						ptr_network->is_connection = TRUE;
				}

				_r_queuedlock_acquireexclusive (&network_context->lock_network);
				_r_obj_addhashtablepointer (network_context->network_ptr, network_hash, ptr_network);
				_r_queuedlock_releaseexclusive (&network_context->lock_network);

				if (is_diagnostic)
					tcp4_diag.added_count += 1;

				_r_queuedlock_acquireexclusive (&network_context->lock_checker);
				_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, _r_obj_reference (ptr_network->path));
				_r_queuedlock_releaseexclusive (&network_context->lock_checker);
			}
		}
	}

	// TCP IPv6
	required_size = 0;
	status = GetExtendedTcpTable (NULL, &required_size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);

	if (is_diagnostic)
	{
		tcp6_diag.first_status = status;
		tcp6_diag.required_size = required_size;
	}

	if (required_size)
	{
		if (allocated_size < required_size)
		{
			buffer = _r_mem_reallocate (buffer, required_size);

			allocated_size = required_size;
		}

		tcp6_table = (PMIB_TCP6TABLE_OWNER_MODULE)buffer;
		status = GetExtendedTcpTable (tcp6_table, &required_size, FALSE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);

		if (is_diagnostic)
			tcp6_diag.second_status = status;

		if (status == NO_ERROR)
		{
			if (is_diagnostic)
				tcp6_diag.entries_count = tcp6_table->dwNumEntries;

			for (ULONG i = 0; i < tcp6_table->dwNumEntries; i++)
			{
				network_hash = _app_network_gethash (
					AF_INET6,
					tcp6_table->table[i].dwOwningPid,
					tcp6_table->table[i].ucRemoteAddr,
					tcp6_table->table[i].dwRemotePort,
					tcp6_table->table[i].ucLocalAddr,
					tcp6_table->table[i].dwLocalPort,
					IPPROTO_TCP,
					tcp6_table->table[i].dwState
				);

				ptr_network = _app_network_getitem (network_hash);

				if (ptr_network)
				{
					if (is_diagnostic)
						tcp6_diag.existing_count += 1;

					_app_network_update_tcp6_stats (ptr_network, &tcp6_table->table[i]);

					_r_queuedlock_acquireexclusive (&network_context->lock_checker);
					_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, NULL);
					_r_queuedlock_releaseexclusive (&network_context->lock_checker);

					_r_obj_dereference (ptr_network);

					continue;
				}

				ptr_network = (PITEM_NETWORK)_r_obj_allocate (sizeof (ITEM_NETWORK), &_app_dereferencenetwork);

				if (!_app_network_getpath (ptr_network, tcp6_table->table[i].dwOwningPid, tcp6_table->table[i].OwningModuleInfo))
				{
					if (is_diagnostic)
						tcp6_diag.path_fail_count += 1;

					_r_obj_dereference (ptr_network);
					continue;
				}

				ptr_network->af = AF_INET6;
				ptr_network->protocol = IPPROTO_TCP;
				ptr_network->protocol_str = _r_obj_createstring (_app_db_getprotoname (ptr_network->protocol, ptr_network->af, L"<unknown protocol>"));

				RtlCopyMemory (ptr_network->remote_addr6.u.Byte, tcp6_table->table[i].ucRemoteAddr, FWP_V6_ADDR_SIZE);
				ptr_network->remote_port = _r_byteswap_ushort ((USHORT)tcp6_table->table[i].dwRemotePort);
				RtlCopyMemory (ptr_network->local_addr6.u.Byte, tcp6_table->table[i].ucLocalAddr, FWP_V6_ADDR_SIZE);
				ptr_network->local_port = _r_byteswap_ushort ((USHORT)tcp6_table->table[i].dwLocalPort);

				ptr_network->state = tcp6_table->table[i].dwState;

				_app_network_update_tcp6_stats (ptr_network, &tcp6_table->table[i]);

				if (tcp6_table->table[i].dwState == MIB_TCP_STATE_ESTAB)
				{
					if (_app_network_isvalidconnection (ptr_network->af, &ptr_network->remote_addr6) || _app_network_isvalidconnection (ptr_network->af, &ptr_network->local_addr6))
						ptr_network->is_connection = TRUE;
				}

				_r_queuedlock_acquireexclusive (&network_context->lock_network);
				_r_obj_addhashtablepointer (network_context->network_ptr, network_hash, ptr_network);
				_r_queuedlock_releaseexclusive (&network_context->lock_network);

				if (is_diagnostic)
					tcp6_diag.added_count += 1;

				_r_queuedlock_acquireexclusive (&network_context->lock_checker);
				_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, _r_obj_reference (ptr_network->path));
				_r_queuedlock_releaseexclusive (&network_context->lock_checker);
			}
		}
	}

	// UDP IPv4
	required_size = 0;
	status = GetExtendedUdpTable (NULL, &required_size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);

	if (is_diagnostic)
	{
		udp4_diag.first_status = status;
		udp4_diag.required_size = required_size;
	}

	if (required_size)
	{
		if (allocated_size < required_size)
		{
			buffer = _r_mem_reallocate (buffer, required_size);

			allocated_size = required_size;
		}

		udp4_table = (PMIB_UDPTABLE_OWNER_MODULE)buffer;
		status = GetExtendedUdpTable (udp4_table, &required_size, FALSE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);

		if (is_diagnostic)
			udp4_diag.second_status = status;

		if (status == NO_ERROR)
		{
			if (is_diagnostic)
				udp4_diag.entries_count = udp4_table->dwNumEntries;

			for (ULONG i = 0; i < udp4_table->dwNumEntries; i++)
			{
				RtlZeroMemory (&local_addr, sizeof (IN_ADDR));

				local_addr.S_un.S_addr = udp4_table->table[i].dwLocalAddr;

				network_hash = _app_network_gethash (AF_INET, udp4_table->table[i].dwOwningPid, NULL, 0, &local_addr, udp4_table->table[i].dwLocalPort, IPPROTO_UDP, 0);

				if (_app_network_isitemfound (network_hash))
				{
					if (is_diagnostic)
						udp4_diag.existing_count += 1;

					_r_queuedlock_acquireexclusive (&network_context->lock_checker);
					_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, NULL);
					_r_queuedlock_releaseexclusive (&network_context->lock_checker);

					continue;
				}

				ptr_network = (PITEM_NETWORK)_r_obj_allocate (sizeof (ITEM_NETWORK), &_app_dereferencenetwork);

				if (!_app_network_getpath (ptr_network, udp4_table->table[i].dwOwningPid, udp4_table->table[i].OwningModuleInfo))
				{
					if (is_diagnostic)
						udp4_diag.path_fail_count += 1;

					_r_obj_dereference (ptr_network);
					continue;
				}

				ptr_network->af = AF_INET;
				ptr_network->protocol = IPPROTO_UDP;
				ptr_network->protocol_str = _r_obj_createstring (_app_db_getprotoname (ptr_network->protocol, ptr_network->af, L"<unknown protocol>"));

				ptr_network->local_addr.S_un.S_addr = udp4_table->table[i].dwLocalAddr;
				ptr_network->local_port = _r_byteswap_ushort ((USHORT)udp4_table->table[i].dwLocalPort);

				if (_app_network_isvalidconnection (ptr_network->af, &ptr_network->local_addr))
					ptr_network->is_connection = TRUE;

				_r_queuedlock_acquireexclusive (&network_context->lock_network);
				_r_obj_addhashtablepointer (network_context->network_ptr, network_hash, ptr_network);
				_r_queuedlock_releaseexclusive (&network_context->lock_network);

				if (is_diagnostic)
					udp4_diag.added_count += 1;

				_r_queuedlock_acquireexclusive (&network_context->lock_checker);
				_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, _r_obj_reference (ptr_network->path));
				_r_queuedlock_releaseexclusive (&network_context->lock_checker);
			}
		}
	}

	// UDP IPv6
	required_size = 0;
	status = GetExtendedUdpTable (NULL, &required_size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);

	if (is_diagnostic)
	{
		udp6_diag.first_status = status;
		udp6_diag.required_size = required_size;
	}

	if (required_size)
	{
		if (allocated_size < required_size)
		{
			buffer = _r_mem_reallocate (buffer, required_size);
			allocated_size = required_size;
		}

		udp6_table = (PMIB_UDP6TABLE_OWNER_MODULE)buffer;
		status = GetExtendedUdpTable (udp6_table, &required_size, FALSE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);

		if (is_diagnostic)
			udp6_diag.second_status = status;

		if (status == NO_ERROR)
		{
			if (is_diagnostic)
				udp6_diag.entries_count = udp6_table->dwNumEntries;

			for (ULONG i = 0; i < udp6_table->dwNumEntries; i++)
			{
				network_hash = _app_network_gethash (AF_INET6, udp6_table->table[i].dwOwningPid, NULL, 0, udp6_table->table[i].ucLocalAddr, udp6_table->table[i].dwLocalPort, IPPROTO_UDP, 0);

				if (_app_network_isitemfound (network_hash))
				{
					if (is_diagnostic)
						udp6_diag.existing_count += 1;

					_r_queuedlock_acquireexclusive (&network_context->lock_checker);
					_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, NULL);
					_r_queuedlock_releaseexclusive (&network_context->lock_checker);

					continue;
				}

				ptr_network = (PITEM_NETWORK)_r_obj_allocate (sizeof (ITEM_NETWORK), &_app_dereferencenetwork);

				if (!_app_network_getpath (ptr_network, udp6_table->table[i].dwOwningPid, udp6_table->table[i].OwningModuleInfo))
				{
					if (is_diagnostic)
						udp6_diag.path_fail_count += 1;

					_r_obj_dereference (ptr_network);
					continue;
				}

				ptr_network->af = AF_INET6;
				ptr_network->protocol = IPPROTO_UDP;
				ptr_network->protocol_str = _r_obj_createstring (_app_db_getprotoname (ptr_network->protocol, ptr_network->af, L"<unknown protocol>"));

				RtlCopyMemory (ptr_network->local_addr6.u.Byte, udp6_table->table[i].ucLocalAddr, FWP_V6_ADDR_SIZE);
				ptr_network->local_port = _r_byteswap_ushort ((USHORT)udp6_table->table[i].dwLocalPort);

				if (_app_network_isvalidconnection (ptr_network->af, &ptr_network->local_addr6))
					ptr_network->is_connection = TRUE;

				_r_queuedlock_acquireexclusive (&network_context->lock_network);
				_r_obj_addhashtablepointer (network_context->network_ptr, network_hash, ptr_network);
				_r_queuedlock_releaseexclusive (&network_context->lock_network);

				if (is_diagnostic)
					udp6_diag.added_count += 1;

				_r_queuedlock_acquireexclusive (&network_context->lock_checker);
				_r_obj_addhashtablepointer (network_context->checker_ptr, network_hash, _r_obj_reference (ptr_network->path));
				_r_queuedlock_releaseexclusive (&network_context->lock_checker);
			}
		}
	}

	if (buffer)
		_r_mem_free (buffer);

	if (is_diagnostic)
	{
		_app_network_writediagnostic (
			L"[DEBUG-netmon] scan cycle=%" TEXT (PR_LONG) L" tcp4 first=%" TEXT (PR_ULONG) L" second=%" TEXT (PR_ULONG) L" required=%" TEXT (PR_ULONG) L" entries=%" TEXT (PR_ULONG) L" existing=%" TEXT (PR_ULONG) L" added=%" TEXT (PR_ULONG) L" path_fail=%" TEXT (PR_ULONG) L" tcp6 first=%" TEXT (PR_ULONG) L" second=%" TEXT (PR_ULONG) L" required=%" TEXT (PR_ULONG) L" entries=%" TEXT (PR_ULONG) L" existing=%" TEXT (PR_ULONG) L" added=%" TEXT (PR_ULONG) L" path_fail=%" TEXT (PR_ULONG) L" udp4 first=%" TEXT (PR_ULONG) L" second=%" TEXT (PR_ULONG) L" required=%" TEXT (PR_ULONG) L" entries=%" TEXT (PR_ULONG) L" existing=%" TEXT (PR_ULONG) L" added=%" TEXT (PR_ULONG) L" path_fail=%" TEXT (PR_ULONG) L" udp6 first=%" TEXT (PR_ULONG) L" second=%" TEXT (PR_ULONG) L" required=%" TEXT (PR_ULONG) L" entries=%" TEXT (PR_ULONG) L" existing=%" TEXT (PR_ULONG) L" added=%" TEXT (PR_ULONG) L" path_fail=%" TEXT (PR_ULONG) L"\r\n",
			cycle_id,
			tcp4_diag.first_status,
			tcp4_diag.second_status,
			tcp4_diag.required_size,
			tcp4_diag.entries_count,
			tcp4_diag.existing_count,
			tcp4_diag.added_count,
			tcp4_diag.path_fail_count,
			tcp6_diag.first_status,
			tcp6_diag.second_status,
			tcp6_diag.required_size,
			tcp6_diag.entries_count,
			tcp6_diag.existing_count,
			tcp6_diag.added_count,
			tcp6_diag.path_fail_count,
			udp4_diag.first_status,
			udp4_diag.second_status,
			udp4_diag.required_size,
			udp4_diag.entries_count,
			udp4_diag.existing_count,
			udp4_diag.added_count,
			udp4_diag.path_fail_count,
			udp6_diag.first_status,
			udp6_diag.second_status,
			udp6_diag.required_size,
			udp6_diag.entries_count,
			udp6_diag.existing_count,
			udp6_diag.added_count,
			udp6_diag.path_fail_count
		);
	}
}

_Ret_maybenull_
PITEM_NETWORK _app_network_getitem (
	_In_ ULONG network_hash
)
{
	PITEM_NETWORK_CONTEXT network_context;
	PITEM_NETWORK ptr_network;

	network_context = _app_network_getcontext ();

	if (!network_context)
		return NULL;

	_r_queuedlock_acquireshared (&network_context->lock_network);
	ptr_network = (PITEM_NETWORK)_r_obj_findhashtablepointer (network_context->network_ptr, network_hash);
	_r_queuedlock_releaseshared (&network_context->lock_network);

	return ptr_network;
}

_Success_ (return != 0)
ULONG _app_network_getappitem (
	_In_ ULONG network_hash
)
{
	PITEM_NETWORK ptr_network;
	ULONG hash_code;

	ptr_network = _app_network_getitem (network_hash);

	if (!ptr_network)
		return 0;

	hash_code = ptr_network->app_hash;

	_r_obj_dereference (ptr_network);

	return hash_code;
}

ULONG _app_network_gethash (
	_In_ ADDRESS_FAMILY af,
	_In_ ULONG pid,
	_In_opt_ LPCVOID remote_addr,
	_In_opt_ ULONG remote_port,
	_In_opt_ LPCVOID local_addr,
	_In_opt_ ULONG local_port,
	_In_ UINT8 proto,
	_In_opt_ ULONG state
)
{
	WCHAR local_address[LEN_IP_MAX] = {0}, remote_address[LEN_IP_MAX] = {0}, network_string[0x100];

	if (remote_addr)
		_app_formatip (remote_address, RTL_NUMBER_OF (remote_address), af, remote_addr, FALSE);

	if (local_addr)
		_app_formatip (local_address, RTL_NUMBER_OF (local_address), af, local_addr, FALSE);

	_r_str_printf (
		network_string,
		RTL_NUMBER_OF (network_string),
		L"%" TEXT (PRIu8) L"_%" TEXT (PR_ULONG) L"_%s_%" TEXT (PR_ULONG) L"_%s_%" TEXT (PR_ULONG) L"_%" TEXT (PRIu8) L"_%" TEXT (PR_ULONG),
		af,
		pid,
		remote_address,
		remote_port,
		local_address,
		local_port,
		proto,
		state
	);

	return _r_str_gethash2 (network_string, TRUE);
}

BOOLEAN _app_network_getpath (
	_Inout_ PITEM_NETWORK ptr_network,
	_In_ ULONG pid,
	_In_opt_ PULONG64 modules
)
{
	static volatile LONG diagnostic_path_fail_count = 0;

	PTOKEN_APPCONTAINER_INFORMATION app_container = NULL;
	PR_STRING process_name = NULL;
	HANDLE hprocess, htoken;
	NTSTATUS appcontainer_status = STATUS_UNSUCCESSFUL;
	NTSTATUS open_status = STATUS_UNSUCCESSFUL;
	NTSTATUS query_nt_status = STATUS_UNSUCCESSFUL;
	NTSTATUS query_win32_status = STATUS_UNSUCCESSFUL;
	NTSTATUS token_status = STATUS_UNSUCCESSFUL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	LONG failure_id;
	ULONG module_tag = 0;

	if (pid == PROC_WAITING_PID)
	{
		ptr_network->app_hash = 0;
		ptr_network->type = DATA_APP_REGULAR;
		ptr_network->path = _r_obj_createstring (PROC_WAITING_NAME);

		return TRUE;
	}
	else if (pid == PROC_SYSTEM_PID)
	{
		ptr_network->app_hash = config.ntoskrnl_hash;
		ptr_network->type = DATA_APP_REGULAR;
		ptr_network->path = _r_obj_createstring (PROC_SYSTEM_NAME);

		return TRUE;
	}

	if (modules)
	{
		module_tag = *(PULONG)modules;
		process_name = _r_sys_querytaginformation (pid, ULongToPtr (module_tag));

		if (process_name)
			ptr_network->type = DATA_APP_SERVICE;
	}

	if (!process_name)
	{
		status = _r_sys_openprocess (&hprocess, pid, PROCESS_QUERY_LIMITED_INFORMATION);
		open_status = status;

		if (NT_SUCCESS (status))
		{
			ptr_network->type = _r_sys_isprocessimmersive (hprocess) ? DATA_APP_UWP : DATA_APP_REGULAR;

			if (ptr_network->type == DATA_APP_UWP)
			{
				status = NtOpenProcessTokenEx (hprocess, TOKEN_QUERY, 0, &htoken);
				token_status = status;

				if (NT_SUCCESS (status))
				{
					status = _r_sys_querytokeninformation ((PVOID_PTR)&app_container, htoken, TokenAppContainerSid);
					appcontainer_status = status;

					if (NT_SUCCESS (status))
					{
						_r_str_fromsid (&process_name, app_container->TokenAppContainer);

						_r_mem_free (app_container);
					}

					NtClose (htoken);
				}
			}

			if (!process_name)
			{
				status = _r_sys_queryprocessstring (&process_name, hprocess, ProcessImageFileNameWin32);
				query_win32_status = status;

				// fix for WSL processes (issue #606)
				if (status == STATUS_UNSUCCESSFUL)
				{
					status = _r_sys_queryprocessstring (&process_name, hprocess, ProcessImageFileName);
					query_nt_status = status;
				}
			}

			NtClose (hprocess);
		}
	}

	if (process_name)
	{
		ptr_network->app_hash = _r_str_gethash (&process_name->sr, TRUE);
		ptr_network->path = process_name;

		return TRUE;
	}

	if (_app_network_isdiagnosticenabled ())
	{
		failure_id = _InterlockedIncrement (&diagnostic_path_fail_count);

		if (failure_id <= 40)
		{
			_app_network_writediagnostic (
				L"[DEBUG-netmon] path-fail id=%" TEXT (PR_LONG) L" pid=%" TEXT (PR_ULONG) L" module_tag=%" TEXT (PR_ULONG) L" open_status=0x%08X token_status=0x%08X appcontainer_status=0x%08X query_win32_status=0x%08X query_nt_status=0x%08X\r\n",
				failure_id,
				pid,
				module_tag,
				(ULONG)open_status,
				(ULONG)token_status,
				(ULONG)appcontainer_status,
				(ULONG)query_win32_status,
				(ULONG)query_nt_status
			);
		}
	}

	return FALSE;
}

BOOLEAN _app_network_isapphaveconnection (
	_In_ ULONG app_hash
)
{
	PITEM_NETWORK_CONTEXT network_context;
	PITEM_NETWORK ptr_network = NULL;
	ULONG_PTR enum_key = 0;

	network_context = _app_network_getcontext ();

	if (!network_context)
		return FALSE;

	_r_queuedlock_acquireshared (&network_context->lock_network);

	while (_r_obj_enumhashtablepointer (network_context->network_ptr, (PVOID_PTR)&ptr_network, NULL, &enum_key))
	{
		if (ptr_network->app_hash != app_hash)
			continue;

		if (ptr_network->is_connection)
		{
			_r_queuedlock_releaseshared (&network_context->lock_network);

			return TRUE;
		}
	}

	_r_queuedlock_releaseshared (&network_context->lock_network);

	return FALSE;
}

BOOLEAN _app_network_isitemfound (
	_In_ ULONG network_hash
)
{
	PITEM_NETWORK_CONTEXT network_context;
	BOOLEAN is_found;

	network_context = _app_network_getcontext ();

	if (!network_context)
		return FALSE;

	_r_queuedlock_acquireshared (&network_context->lock_network);
	is_found = (_r_obj_findhashtable (network_context->network_ptr, network_hash) != NULL);
	_r_queuedlock_releaseshared (&network_context->lock_network);

	return is_found;
}

BOOLEAN _app_network_isvalidconnection (
	_In_ ADDRESS_FAMILY af,
	_In_ LPCVOID address
)
{
	PIN6_ADDR p6addr;
	PIN_ADDR p4addr;

	switch (af)
	{
		case AF_INET:
		{
			p4addr = (const PIN_ADDR)address;

			return (!IN4_IS_ADDR_UNSPECIFIED (p4addr) &&
					!IN4_IS_ADDR_LOOPBACK (p4addr) &&
					!IN4_IS_ADDR_LINKLOCAL (p4addr) &&
					!IN4_IS_ADDR_MULTICAST (p4addr) &&
					!IN4_IS_ADDR_MC_ADMINLOCAL (p4addr) &&
					!IN4_IS_ADDR_RFC1918 (p4addr));
		}

		case AF_INET6:
		{
			p6addr = (const PIN6_ADDR)address;

			return (!IN6_IS_ADDR_UNSPECIFIED (p6addr) &&
					!IN6_IS_ADDR_LOOPBACK (p6addr) &&
					!IN6_IS_ADDR_ANYCAST (p6addr) &&
					!IN6_IS_ADDR_LINKLOCAL (p6addr) &&
					!IN6_IS_ADDR_MULTICAST (p6addr) &&
					!IN6_IS_ADDR_SITELOCAL (p6addr));
		}

		default:
		{
			return FALSE; // unknown address family
		}
	}
}

VOID _app_network_printlistviewtable (
	_Inout_ PITEM_NETWORK_CONTEXT network_context
)
{
	PITEM_NETWORK ptr_network = NULL;
	PR_STRING string;
	ULONG_PTR enum_key = 0;
	ULONG app_hash, network_hash, add_call_count = 0, enum_count = 0, queued_count = 0, removed_count = 0;
	INT item_count, item_count_after_add = 0, item_count_after_remove = 0, item_count_before = 0;
	BOOLEAN is_diagnostic;
	BOOLEAN is_highlight = FALSE, is_refresh = FALSE;

	is_diagnostic = _app_network_isdiagnosticenabled ();

	if (is_diagnostic)
		item_count_before = _r_listview_getitemcount (network_context->hwnd, IDC_NETWORK);

	if (_r_config_getboolean (L"IsEnableHighlighting", TRUE, NULL) && _r_config_getboolean (L"IsHighlightConnection", TRUE, L"colors"))
		is_highlight = TRUE;

	// add new connections into listview
	_r_queuedlock_acquireshared (&network_context->lock_network);

	while (_r_obj_enumhashtablepointer (network_context->network_ptr, (PVOID_PTR)&ptr_network, &network_hash, &enum_key))
	{
		if (is_diagnostic)
			enum_count += 1;

		string = (PR_STRING)_r_obj_findhashtablepointer (network_context->checker_ptr, network_hash);

		if (!string)
			continue;

		if (is_diagnostic)
			queued_count += 1;

		_app_listview_addnetworkitem (network_context->hwnd, network_hash);

		if (is_diagnostic)
			add_call_count += 1;

		if (ptr_network->path && ptr_network->app_hash)
			_app_getfileinformation (ptr_network->path, ptr_network->app_hash, ptr_network->type, IDC_NETWORK);

		// resolve network address
		_app_queue_resolver (network_context->hwnd, IDC_NETWORK, network_hash, ptr_network);

		_r_obj_dereference (string);

		is_refresh = TRUE;
	}

	_r_queuedlock_releaseshared (&network_context->lock_network);

	// refresh network tab (traffic counters change on every pass)
	if (is_refresh)
	{
		_app_listview_updateby_id (network_context->hwnd, IDC_NETWORK, PR_UPDATE_NORESIZE);
	}
	else
	{
		_r_listview_redraw (network_context->hwnd, IDC_NETWORK);
		_app_listview_sort (network_context->hwnd, IDC_NETWORK, INT_ERROR, FALSE);
	}

	// remove closed connections from list
	item_count = _r_listview_getitemcount (network_context->hwnd, IDC_NETWORK);
	item_count_after_add = item_count;

	if (!item_count)
	{
		if (is_diagnostic)
		{
			_app_network_writediagnostic (
				L"[DEBUG-netmon] print before=%" TEXT (PR_LONG) L" after_add=%" TEXT (PR_LONG) L" after_remove=%" TEXT (PR_LONG) L" network_enum=%" TEXT (PR_ULONG) L" queued=%" TEXT (PR_ULONG) L" add_calls=%" TEXT (PR_ULONG) L" removed=%" TEXT (PR_ULONG) L" refresh=%" TEXT (PR_ULONG) L"\r\n",
				item_count_before,
				item_count_after_add,
				item_count_after_add,
				enum_count,
				queued_count,
				add_call_count,
				removed_count,
				(ULONG)is_refresh
			);
		}

		return;
	}

	for (INT i = item_count - 1; i != INT_ERROR; i--)
	{
		network_hash = (ULONG)_app_listview_getitemcontext (network_context->hwnd, IDC_NETWORK, i);

		if (_r_obj_findhashtable (network_context->checker_ptr, network_hash))
			continue;

		_r_listview_deleteitem (network_context->hwnd, IDC_NETWORK, i);

		if (is_diagnostic)
			removed_count += 1;

		app_hash = _app_network_getappitem (network_hash);

		_app_network_removeitem (network_hash);

		if (app_hash && is_highlight)
			_app_listview_updateby_param (network_context->hwnd, app_hash, PR_SETITEM_REDRAW, TRUE); // redraw listview item
	}

	if (is_diagnostic)
	{
		item_count_after_remove = _r_listview_getitemcount (network_context->hwnd, IDC_NETWORK);

		_app_network_writediagnostic (
			L"[DEBUG-netmon] print before=%" TEXT (PR_LONG) L" after_add=%" TEXT (PR_LONG) L" after_remove=%" TEXT (PR_LONG) L" network_enum=%" TEXT (PR_ULONG) L" queued=%" TEXT (PR_ULONG) L" add_calls=%" TEXT (PR_ULONG) L" removed=%" TEXT (PR_ULONG) L" refresh=%" TEXT (PR_ULONG) L"\r\n",
			item_count_before,
			item_count_after_add,
			item_count_after_remove,
			enum_count,
			queued_count,
			add_call_count,
			removed_count,
			(ULONG)is_refresh
		);
	}
}

VOID _app_network_removeitem (
	_In_ ULONG network_hash
)
{
	PITEM_NETWORK_CONTEXT network_context;

	network_context = _app_network_getcontext ();

	if (!network_context)
		return;

	_r_queuedlock_acquireexclusive (&network_context->lock_network);
	_r_obj_removehashtableitem (network_context->network_ptr, network_hash);
	_r_queuedlock_releaseexclusive (&network_context->lock_network);
}

VOID NTAPI _app_network_threadproc (
	_In_ PVOID arglist
)
{
	PITEM_NETWORK_CONTEXT network_context;

	network_context = (PITEM_NETWORK_CONTEXT)arglist;

	_app_network_writediagnostic (L"[DEBUG-netmon] thread started context=0x%p hwnd=0x%p\r\n", network_context, network_context->hwnd);

	while (TRUE)
	{
		// update network table
		_app_network_generatetable (network_context);
		_app_network_printlistviewtable (network_context);

		_r_sys_waitforsingleobject (NtCurrentThread (), 2000);
	}

	_app_network_uninitialize (network_context);
}
