rule trojan_checker 
{
    strings:
        $vp = "VirtualProtect"
        $vp_w = "VirtualProtect" wide

        $va = "VirtualAlloc"
        $va_w = "VirtualAlloc" wide

        $ivs = "IsValidSid"
        $ivs_w = "IsValidSid" wide

        $nb = "Netbios"
        $nb_w = "Netbios" wide

        $se = "ShellExecute"
        $se_w = "ShellExecute" wide

        $urldtf = "URLDownloadToFile"
        $urldtf_w = "URLDownloadToFile" wide

        $ftppf = "FtpPutFile"
        $ftppf_w = "FtpPutFile" wide

        $send = "send"
        $send_w = "send" wide

        $ws2 = "WS2_32.dll"
        $ws2_w = "WS2_32.dll" wide

        $upx = "UPX!" nocase
        $upx_w = "UPX!" nocase wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (($vp or $vp_w) and ($va or $va_w) and ($ivs or $ivs_w))
            or
            (($se or $se_w) and ($nb or $nb_w))
            or 
            (($urldtf or $urldtf_w) or ($ftppf or $ftppf_w) and ($ws2 or $ws2_w) and ($send or $send_w))
        )
        and
        ($upx or $upx_w)
}

rule adware_checker 
{
    strings:
        $slv32 = "SysListView32"
        $slv32_w = "SysListView32" wide

        $file_delete = "DeleteFile"
        $file_delete_w = "DeleteFile" wide

        $find_first_file = "FindFirstFile"
        $find_first_file_w = "FindFirstFile" wide

        $find_next_file = "FindNextFile"
        $find_next_file_w = "FindNextFile" wide

        $write_file = "WriteFile"
        $write_file_w = "WriteFile" wide

        $search_path = "SearchPath"
        $search_path_w = "SearchPath" wide

        $create_directory = "CreateDirectory"
        $create_directory_w = "CreateDirectory" wide

        $remove_directory = "RemoveDirectory"
        $remove_directory_w = "RemoveDirectory" wide

        $copy_file = "CopyFile"
        $copy_file_w = "CopyFile" wide

        $create_process = "CreateProcess"
        $create_process_w = "CreateProcess" wide
    
    condition:
        uint16(0) == 0x5A4D
        and
        ($slv32 or $slv32_w)
        or
        (
            ($file_delete or $file_delete_w)
            and
            ($find_first_file or $find_first_file_w)
            and
            ($find_next_file or $find_next_file_w)
            and
            ($write_file or $write_file_w)
            and
            ($search_path or $search_path_w)
            and
            ($create_directory or $create_directory_w)
            and
            ($remove_directory or $remove_directory_w)
            and
            ($copy_file or $copy_file_w)
            and
            ($create_process or $create_process_w)
        )
        // or
        // (
        //     ($reg_enum_key or $reg_enum_key_w)
        //     and
        //     ($reg_create_key_ex or $reg_create_key_ex_w)
        //     and
        //     ($reg_delete_value or $ref_delete_value_w)
        //     and
        //     ($reg_delete_key or $reg_delete_key_w)
        // )
}