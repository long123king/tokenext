# tokenext
A windbg extension, extracting token related contents

Usage:

1. compile this project to get a **tokenext.dll** file 

2. move **tokenext.dll** to **[WINDBG_DIR]/winext**  
 
3. in windbg, load this extention with command:  

        .load tokenext.dll;

4. run a command, such as handles like this:

        !dk handles

5. supported commands and options:  

        !dk cmd [address] [options]
        commands:
                pses - dump all active processes
                gobj - dump all global object, same as WinObj
             handles - dump all open handles by a specific process
            khandles - dump all kernle open handles
               types - dump all object types
             dbgdata - dump all debug data
             process - dump a specific process
                 obj - dump a specific object header
        handle_table - dump a specific process's handle table
               token - dump a specific token
                 sdr - dump a specific security descriptor [relative]
                 acl - dump a specific acl
                 sid - dump a specific sid
            sessions - dump all logon sessions
        options:
                  /f - dump all related fields in detail
                 /po - dump related process object header
                 /to - dump related token object header
                  /r - dump object directory recursively
                  /o - dump related object header
                 /ht - dump related handle table
              /token - dump related token
               /link - dump linked token
