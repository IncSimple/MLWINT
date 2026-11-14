"""Reviewed descriptions of selected capa static rules.

These describe matched patterns, not observed execution or successful actions.
The mappings apply to any analyzed file with the same rule match.
"""

EXPLANATIONS = {
    "accept command line arguments": (
        "Patterns support accepting arguments supplied "
        "when starting the program."
    ),
    "check if file exists": (
        "Patterns support checking whether a file exists."
    ),
    "contains PDB path": (
        "A debugging-symbol (PDB) path was found in the file. "
        "This is a content finding, not proof that the program "
        "searches for PDB files."
    ),
    "create process on Windows": (
        "Patterns support starting another Windows process."
    ),
    "enumerate files on Windows": (
        "Patterns support listing files on Windows."
    ),
    "get file attributes": (
        "Patterns support querying file properties."
    ),
    "get file size": (
        "Patterns support querying a file's size."
    ),
    "link function at runtime on Windows": (
        "Patterns support resolving functions at runtime. "
        "This alone does not establish evasion."
    ),
    "parse PE header": (
        "Patterns support inspecting Windows executable headers."
    ),
    "print debug messages": (
        "Patterns support sending debugging messages."
    ),
    "query environment variable": (
        "Patterns support reading environment variables."
    ),
    "read file on Windows": (
        "Patterns support opening and reading files. "
        "Actual file paths and runtime access were not observed."
    ),
    "reference analysis tools strings": (
        "Strings resembling analysis-tool names were found. "
        "This match does not establish that the program "
        "detects or evades those tools."
    ),
    "set environment variable": (
        "Patterns support setting environment variables. "
        "This alone does not establish persistence."
    ),
    "terminate process": (
        "Patterns support ending a process. "
        "The target and actual runtime use are unknown."
    ),
    "write file on Windows": (
        "Patterns support writing file contents. "
        "Actual target files, modifications and damage "
        "were not observed."
    ),
    "acquire debug privileges": (
        "Debug-privilege-related patterns matched. "
        "This capa rule can match the SeDebugPrivilege "
        "string alone. It does not establish that debug "
        "privileges were acquired or enabled."
    ),
    "check for time delay via GetTickCount": (
        "The rule matched repeated GetTickCount references "
        "together with timing arithmetic/comparison patterns. "
        "This does not establish debugger detection "
        "or an attempt to evade analysis."
    ),
    "compare security identifiers": (
        "Patterns support comparing Windows security "
        "identifiers (SIDs). Comparing identifiers does "
        "not itself change identity or privileges."
    ),
    "get file version info": (
        "Patterns support retrieving version metadata "
        "from a file. This does not establish which file "
        "was queried at runtime."
    ),
    "get session user name": (
        "Patterns support retrieving user/account-name "
        "information. This does not establish password "
        "access, credential theft or data transmission."
    ),
    "get token privileges": (
        "Patterns support querying the privileges listed "
        "in a Windows access token. GetTokenInformation "
        "with TokenPrivileges reads that information; "
        "it does not grant, enable or modify privileges."
    ),
    "modify access privileges": (
        "Patterns reference adjustment of token privileges. "
        "AdjustTokenPrivileges can enable, disable or remove "
        "privileges already present in a token; it cannot "
        "add new ones. Actual invocation and success "
        "were not observed."
    ),
}