// simplewall modified fork
// Compatibility with the last publicly available henrypp/routine SDK.
// Copyright (c) 2026 simplewall fork contributors
//
// This file must remain limited to API-shape adapters. It must not change
// simplewall policy or Windows Filtering Platform behavior.

#pragma once

typedef PR_STRINGREF PCR_STRINGREF;
typedef const SID *PCSID;

#define PR_SIZE_BUFFER_MINIMUM PR_SIZE_BUFFER_OVERFLOW
#define GENERAL_ID 666

typedef BOOL (WINAPI *CCAHFFH2) (
	_In_ HCATADMIN hcat_admin,
	_In_ HANDLE hfile,
	_Inout_ DWORD *hash_length,
	_Out_writes_bytes_to_opt_ (*hash_length, *hash_length) BYTE *hash,
	_Reserved_ DWORD flags
);

typedef BOOL (WINAPI *CCAAC2) (
	_Out_ HCATADMIN *hcat_admin,
	_In_opt_ const GUID *subsystem,
	_In_opt_ PCWSTR hash_algorithm,
	_In_opt_ PCCERT_STRONG_SIGN_PARA strong_hash_policy,
	_Reserved_ DWORD flags
);

FORCEINLINE ULONG _r_compat_str_gethash_ref (
	_In_ PR_STRINGREF string,
	_In_ BOOLEAN is_ignorecase
)
{
	return _r_str_gethash2 (string, is_ignorecase);
}

FORCEINLINE ULONG _r_compat_str_gethash_raw (
	_In_ LPWSTR string,
	_In_ BOOLEAN is_ignorecase
)
{
	return _r_str_gethash (string, is_ignorecase);
}

#define _r_config_getboolean(key_name, def_value, section_name) \
	_r_config_getboolean_ex ((key_name), (def_value), (section_name))

#define _r_config_getlong(key_name, def_value, section_name) \
	_r_config_getlong_ex ((key_name), (def_value), (section_name))

#define _r_config_getlong64(key_name, def_value, section_name) \
	_r_config_getlong64_ex ((key_name), (def_value), (section_name))

#define _r_config_getulong(key_name, def_value, section_name) \
	_r_config_getulong_ex ((key_name), (def_value), (section_name))

#define _r_config_setboolean(key_name, value, section_name) \
	_r_config_setboolean_ex ((key_name), (value), (section_name))

#define _r_config_setlong(key_name, value, section_name) \
	_r_config_setlong_ex ((key_name), (value), (section_name))

#define _r_config_setlong64(key_name, value, section_name) \
	_r_config_setlong64_ex ((key_name), (value), (section_name))

#define _r_config_setulong(key_name, value, section_name) \
	_r_config_setulong_ex ((key_name), (value), (section_name))

#define _r_config_getstringexpand(key_name, def_value, section_name) \
	_r_config_getstringexpand_ex ((key_name), (def_value), (section_name))

#define _r_config_setstringexpand(key_name, value, section_name) \
	_r_config_setstringexpand_ex ((key_name), (value), (section_name))

#define _r_config_getfont(key_name, logfont, dpi_value, section_name) \
	_r_config_getfont_ex ((key_name), (logfont), (dpi_value), (section_name))

#define _r_config_setfont(key_name, logfont, dpi_value, section_name) \
	_r_config_setfont_ex ((key_name), (logfont), (dpi_value), (section_name))

#define _r_obj_addlistitem(list_node, list_item, new_index_ptr) \
	_r_obj_addlistitem_ex ((list_node), (list_item), (new_index_ptr))

#define _r_str_gethash _r_compat_str_gethash_ref
#define _r_str_gethash2 _r_compat_str_gethash_raw

#define _r_theme_initialize(hwnd) \
	_r_theme_initialize ((hwnd), _r_theme_isenabled ())

#define _r_format_interval(seconds) \
	_r_format_interval ((seconds), FALSE)

#define _r_imagelist_create(out_buffer, width, height, flags, initial_count, grow_count) \
	_r_imagelist_create ((width), (height), (flags), (initial_count), (grow_count), (out_buffer))

#define _r_imagelist_setsize(himg, width, height) \
	_r_imagelist_setsize ((himg), (width))

#define _r_res_loadimage(out_buffer, hinst, type, name, format, width, height) \
	_r_res_loadimage ((hinst), (type), (name), (format), (width), (height), (out_buffer))

#define _r_fs_openfile(out_buffer, path, desired_access, share_access, open_options, is_directory) \
	_r_fs_openfile ((path), (desired_access), (share_access), (open_options), (is_directory), (out_buffer))

#define _r_sys_openprocess(out_buffer, process_id, desired_access) \
	_r_sys_openprocess (ULongToHandle (process_id), (desired_access), (out_buffer))

#define _r_sys_queryprocessstring(out_buffer, process_handle, info_class) \
	_r_sys_queryprocessstring ((process_handle), (info_class), (out_buffer))

#define _r_sys_querytokeninformation(out_buffer, token_handle, token_class) \
	_r_sys_querytokeninformation ((token_handle), (token_class), (out_buffer))

#define _r_sys_setprocessprivilege(hwnd, process_handle, privileges, count, is_enable) \
	_r_sys_setprocessprivilege ((process_handle), (privileges), (count), (is_enable))

#define _r_str_fromguid(out_buffer, guid, is_uppercase) \
	_r_str_fromguid ((LPGUID)(guid), (is_uppercase), (out_buffer))

#define _r_unixtime_to_filetime(file_time, unixtime) \
	_r_unixtime_to_filetime ((unixtime), (file_time))

#define _r_sys_getservicesid(out_buffer, name) \
	_r_sys_getservicesid ((LPWSTR)(name), (out_buffer))

#define _r_str_environmentexpandstring(out_buffer, environment, name) \
	_r_str_environmentexpandstring ((environment), (name), (out_buffer))

#define _r_path_geticon(path, out_hicon, out_icon_id) \
	_r_path_geticon ((path), (out_icon_id), (out_hicon))

#define _r_fs_createfile(out_buffer, path, create_disposition, desired_access, share_access, file_attributes, create_option, is_directory, allocation_size) \
	_r_fs_createfile ((path), (create_disposition), (desired_access), (share_access), (file_attributes), (create_option), (is_directory), (allocation_size), (out_buffer))

#define _r_sys_loadicon(out_buffer, hinst, icon_name, icon_size) \
	_r_sys_loadicon ((hinst), (icon_name), (icon_size), (out_buffer))

#define _r_reg_openkey(out_buffer, hroot, path, flags, desired_access) \
	_r_reg_openkey ((hroot), (LPWSTR)(path), (flags), (desired_access), (out_buffer))

#define _r_sys_loadlibrary2(out_buffer, lib_name, lib_flags) \
	_r_sys_loadlibrary2 ((lib_name), (lib_flags), (out_buffer))

#define _r_sys_loadlibraryasresource(out_buffer, path) \
	_r_sys_loadlibraryasresource ((path), (out_buffer))

#define _r_sys_compressbuffer(out_buffer, format, buffer) \
	_r_sys_compressbuffer ((format), (buffer), (out_buffer))

#define _r_sys_decompressbuffer(out_buffer, format, buffer) \
	_r_sys_decompressbuffer ((format), (buffer), (out_buffer))

#define _r_res_loadresource(out_buffer, hinst, type, name, lang_id) \
	_r_res_loadresource ((hinst), (type), (name), (lang_id), (out_buffer))

#define _r_res_queryversion(out_buffer, ver_block) \
	_r_res_queryversion ((ver_block), (out_buffer))

#define _r_crypt_getfilehash(out_buffer, algorithm_id, path, hfile) \
	_r_crypt_getfilehash ((algorithm_id), (path), (hfile), (out_buffer))

#define _r_imagelist_getsystem(out_buffer, icons_size) \
	_r_imagelist_getsystem ((icons_size), (out_buffer))

#define _r_button_checkradio _r_ctrl_checkradio
#define _r_button_ischecked _r_ctrl_isbuttonchecked
#define _r_button_isradiochecked _r_ctrl_isradiochecked
#define _r_button_setcheck _r_ctrl_checkbutton
#define _r_button_seticon _r_ctrl_seticon
#define _r_button_setmargins _r_ctrl_setbuttonmargins
#define _r_edit_setmargin _r_ctrl_settextmargin
#define _r_edit_setreadonly _r_ctrl_setreadonly
#define _r_edit_showballoontip _r_ctrl_showballoontip
#define _r_fs_isexists _r_fs_exists
#define _r_obj_isbyteempty _r_obj_isbyteempty2
#define _r_tooltip_create _r_ctrl_createtip
#define _r_tooltip_settext _r_ctrl_settiptext
#define _r_updown_setacceleration _r_ctrl_setacceleration
#define _r_wnd_sendcommand _r_ctrl_sendcommand
#define _r_wnd_topzoder _r_wnd_top

#define _r_menu_addseparator(hmenu) \
	_r_menu_additem_ex ((hmenu), 0, NULL, MF_SEPARATOR)

#define _r_listview_scroll(hwnd, ctrl_id, distance) \
	((VOID)_r_wnd_sendmessage ((hwnd), (ctrl_id), LVM_SCROLL, 0, (LPARAM)(distance)))

#define _r_rebar_getinfo(hwnd, ctrl_id, band_id, out_buffer) \
	((BOOLEAN)!!_r_wnd_sendmessage ((hwnd), (ctrl_id), RB_GETBANDINFOW, (band_id), (LPARAM)(out_buffer)))

#define _r_rebar_setinfo(hwnd, ctrl_id, band_id, buffer) \
	((BOOLEAN)!!_r_wnd_sendmessage ((hwnd), (ctrl_id), RB_SETBANDINFOW, (band_id), (LPARAM)(buffer)))

#define _r_toolbar_getidealsize(hwnd, ctrl_id, is_vertical, out_buffer) \
	((BOOLEAN)!!_r_wnd_sendmessage ((hwnd), (ctrl_id), TB_GETIDEALSIZE, (is_vertical), (LPARAM)(out_buffer)))

#define _r_toolbar_setbutton(hwnd, ctrl_id, command_id, string, style, state, image) \
	_r_toolbar_setbutton ((hwnd), (ctrl_id), (command_id), (LPWSTR)(string), (style), (state), (image))

#define _r_sys_settimer(hwnd, timer_id, timeout, callback) \
	SetTimer ((hwnd), (timer_id), (timeout), (callback))

#define _r_sys_terminatethread(thread_handle, exit_status) \
	NtTerminateThread ((thread_handle), (exit_status))

#define _r_edit_setselection(hwnd, ctrl_id, start_pos, end_pos) \
	((VOID)_r_wnd_sendmessage ((hwnd), (ctrl_id), EM_SETSEL, (start_pos), (end_pos)))

#define _r_tab_selectitem(hwnd, ctrl_id, item_id) \
	((INT)_r_wnd_sendmessage ((hwnd), (ctrl_id), TCM_SETCURSEL, (item_id), 0))

#define _r_path_getbasename2(path) PathFindFileNameW (path)
#define _r_path_getdrivenumber(path) PathGetDriveNumberW ((path)->buffer)
#define _r_path_isnetwork(path) PathIsNetworkPathW ((path)->buffer)

#define _r_obj_initializestringref(string, buffer) \
	_r_obj_initializestringref ((string), (LPWSTR)(buffer))

#define _r_filedialog_setpath(file_dialog, path) \
	_r_filedialog_setpath ((file_dialog), (path)->buffer)

#define _r_listview_setstyle(hwnd, ctrl_id, ex_style, is_groupview) \
	_r_listview_setstyle ((hwnd), (ctrl_id), (ULONG)(ex_style), (is_groupview))

#define _r_sys_createthread(thread_handle, hprocess, base_address, arglist, environment, thread_name) \
	_r_sys_createthread ((thread_handle), (hprocess), (PUSER_THREAD_START_ROUTINE)(base_address), (arglist), (environment), (thread_name))

#define _r_menu_setitemtext(hmenu, item_id, is_byposition, string) \
	_r_menu_setitemtext ((hmenu), (item_id), (is_byposition), (LPWSTR)(string))

#define _r_menu_popup(hmenu, hwnd, point, is_sendmessage) \
	_r_menu_popup ((hmenu), (hwnd), (point), (BOOLEAN)(is_sendmessage))

#define _r_calc_filetime2largeinteger(out_buffer, file_time) \
	_r_calc_filetime2largeinteger ((file_time), (out_buffer))

#define _r_sys_getprocessimagepathbyid(out_buffer, process_id, is_ntpathtodos) \
	_r_sys_getprocessimagepathbyid (ULongToHandle (process_id), (is_ntpathtodos), (out_buffer))

#define _r_sys_querytaginformation(process_id, tag) \
	_r_sys_querytaginformation (ULongToHandle (process_id), (tag))

#define _r_sys_getusername(out_buffer, sid, is_withdomain) \
	_r_sys_getusername ((sid), (is_withdomain), (out_buffer))

FORCEINLINE NTSTATUS _r_compat_fs_setpos (
	_In_ HANDLE hfile,
	_In_ LONG64 new_pos
)
{
	LARGE_INTEGER position;

	position.QuadPart = new_pos;
	return _r_fs_setpos (hfile, &position);
}

#define _r_fs_getsize(path, hfile, out_buffer) \
	_r_fs_getsize2 ((path), (hfile), (out_buffer))

#define _r_fs_setpos _r_compat_fs_setpos

FORCEINLINE NTSTATUS _r_compat_sys_createprocess (
	_In_opt_ PR_STRINGREF file_name,
	_In_opt_ PR_STRINGREF command_line,
	_In_opt_ PR_STRINGREF directory,
	_In_ BOOLEAN is_wait
)
{
	return _r_sys_createprocess (
		file_name ? file_name->buffer : NULL,
		command_line ? command_line->buffer : NULL,
		directory ? directory->buffer : NULL,
		is_wait
	);
}

#define _r_sys_createprocess _r_compat_sys_createprocess

FORCEINLINE BOOLEAN _r_compat_obj_enumhashtable (
	_In_ PR_HASHTABLE hashtable,
	_Out_opt_ PVOID_PTR entry_ptr,
	_Out_opt_ PULONG hash_code_ptr,
	_Inout_ PULONG_PTR enum_key
)
{
	ULONG_PTR hash_code;
	BOOLEAN result;

	result = _r_obj_enumhashtable (
		hashtable,
		entry_ptr,
		hash_code_ptr ? &hash_code : NULL,
		enum_key
	);

	if (result && hash_code_ptr)
		*hash_code_ptr = (ULONG)hash_code;

	return result;
}

FORCEINLINE BOOLEAN _r_compat_obj_enumhashtablepointer (
	_In_ PR_HASHTABLE hashtable,
	_Out_opt_ PVOID_PTR entry_ptr,
	_Out_opt_ PULONG hash_code_ptr,
	_Inout_ PULONG_PTR enum_key
)
{
	ULONG_PTR hash_code;
	BOOLEAN result;

	result = _r_obj_enumhashtablepointer (
		hashtable,
		entry_ptr,
		hash_code_ptr ? &hash_code : NULL,
		enum_key
	);

	if (result && hash_code_ptr)
		*hash_code_ptr = (ULONG)hash_code;

	return result;
}

#define _r_obj_enumhashtable _r_compat_obj_enumhashtable
#define _r_obj_enumhashtablepointer _r_compat_obj_enumhashtablepointer

#ifndef IN6_IS_ADDR_ULA
#define IN6_IS_ADDR_ULA(address) \
	((((const UCHAR *)(address))[0] & 0xFE) == 0xFC)
#endif

FORCEINLINE BOOLEAN _r_compat_wnd_setcontext (
	_In_ HWND hwnd,
	_In_ ULONG property_id,
	_In_ PVOID context
)
{
	_r_wnd_setcontext (hwnd, property_id, context);
	return TRUE;
}

FORCEINLINE BOOLEAN _r_compat_wnd_removecontext (
	_In_ HWND hwnd,
	_In_ ULONG property_id
)
{
	_r_wnd_removecontext (hwnd, property_id);
	return TRUE;
}

#define _r_wnd_setcontext _r_compat_wnd_setcontext
#define _r_wnd_removecontext _r_compat_wnd_removecontext

FORCEINLINE NTSTATUS _r_fs_createhardlink (
	_In_ PR_STRINGREF existing_path,
	_In_ PR_STRINGREF link_path
)
{
	if (CreateHardLinkW (link_path->buffer, existing_path->buffer, NULL))
		return STATUS_SUCCESS;

	return _r_sys_doserrortontstatus (GetLastError ());
}

FORCEINLINE BOOLEAN _r_config_invertboolean (
	_In_ LPCWSTR key_name,
	_In_ BOOLEAN def_value,
	_In_opt_ LPCWSTR section_name
)
{
	BOOLEAN value;

	value = !_r_config_getboolean_ex (key_name, def_value, section_name);
	_r_config_setboolean_ex (key_name, value, section_name);

	return value;
}
