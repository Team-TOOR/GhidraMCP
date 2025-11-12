# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "requests>=2,<3",
#     "mcp>=1.2.0,<2",
# ]
# ///

import sys
import requests
import argparse
import logging
from urllib.parse import urljoin

from mcp.server.fastmcp import FastMCP

DEFAULT_GHIDRA_SERVER = "http://127.0.0.1:8080/"

logger = logging.getLogger(__name__)

mcp = FastMCP("ghidra-mcp")

# Initialize ghidra_server_url with default value
ghidra_server_url = DEFAULT_GHIDRA_SERVER

def safe_get(endpoint: str, params: dict = None) -> list:
    """
    Perform a GET request with optional query parameters.
    """
    if params is None:
        params = {}

    url = urljoin(ghidra_server_url, endpoint)

    try:
        response = requests.get(url, params=params, timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.splitlines()
        else:
            return [f"Error {response.status_code}: {response.text.strip()}"]
    except Exception as e:
        return [f"Request failed: {str(e)}"]

def safe_post(endpoint: str, data: dict | str) -> str:
    try:
        url = urljoin(ghidra_server_url, endpoint)
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        response.encoding = 'utf-8'
        if response.ok:
            return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

@mcp.tool()
def list_methods(offset: int = 0, limit: int = 100) -> list:
    """
    List all function names in the program with pagination.
    """
    return safe_get("methods", {"offset": offset, "limit": limit})

@mcp.tool()
def list_classes(offset: int = 0, limit: int = 100) -> list:
    """
    List all namespace/class names in the program with pagination.
    """
    return safe_get("classes", {"offset": offset, "limit": limit})

@mcp.tool()
def decompile_function(name: str) -> str:
    """
    Decompile a specific function by name and return the decompiled C code.
    """
    return safe_post("decompile", name)

@mcp.tool()
def rename_function(old_name: str, new_name: str) -> str:
    """
    Rename a function by its current name to a new user-defined name.
    """
    return safe_post("renameFunction", {"oldName": old_name, "newName": new_name})

@mcp.tool()
def rename_data(address: str, new_name: str) -> str:
    """
    Rename a data label at the specified address.
    """
    return safe_post("renameData", {"address": address, "newName": new_name})

@mcp.tool()
def list_segments(offset: int = 0, limit: int = 100) -> list:
    """
    List all memory segments in the program with pagination.
    """
    return safe_get("segments", {"offset": offset, "limit": limit})

@mcp.tool()
def list_imports(offset: int = 0, limit: int = 100) -> list:
    """
    List imported symbols in the program with pagination.
    """
    return safe_get("imports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_exports(offset: int = 0, limit: int = 100) -> list:
    """
    List exported functions/symbols with pagination.
    """
    return safe_get("exports", {"offset": offset, "limit": limit})

@mcp.tool()
def list_namespaces(offset: int = 0, limit: int = 100) -> list:
    """
    List all non-global namespaces in the program with pagination.
    """
    return safe_get("namespaces", {"offset": offset, "limit": limit})

@mcp.tool()
def list_data_items(offset: int = 0, limit: int = 100) -> list:
    """
    List defined data labels and their values with pagination.
    """
    return safe_get("data", {"offset": offset, "limit": limit})

@mcp.tool()
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> list:
    """
    Search for functions whose name contains the given substring.
    """
    if not query:
        return ["Error: query string is required"]
    return safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

@mcp.tool()
def rename_variable(function_name: str, old_name: str, new_name: str) -> str:
    """
    Rename a local variable within a function.
    """
    return safe_post("renameVariable", {
        "functionName": function_name,
        "oldName": old_name,
        "newName": new_name
    })

@mcp.tool()
def get_function_by_address(address: str) -> str:
    """
    Get a function by its address.
    """
    return "\n".join(safe_get("get_function_by_address", {"address": address}))

@mcp.tool()
def get_current_address() -> str:
    """
    Get the address currently selected by the user.
    """
    return "\n".join(safe_get("get_current_address"))

@mcp.tool()
def get_current_function() -> str:
    """
    Get the function currently selected by the user.
    """
    return "\n".join(safe_get("get_current_function"))

@mcp.tool()
def list_functions() -> list:
    """
    List all functions in the database.
    """
    return safe_get("list_functions")

@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    """
    Decompile a function at the given address.
    """
    return "\n".join(safe_get("decompile_function", {"address": address}))

@mcp.tool()
def disassemble_function(address: str) -> list:
    """
    Get assembly code (address: instruction; comment) for a function.
    """
    return safe_get("disassemble_function", {"address": address})

@mcp.tool()
def set_decompiler_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function pseudocode.
    """
    return safe_post("set_decompiler_comment", {"address": address, "comment": comment})

@mcp.tool()
def set_disassembly_comment(address: str, comment: str) -> str:
    """
    Set a comment for a given address in the function disassembly.
    """
    return safe_post("set_disassembly_comment", {"address": address, "comment": comment})

@mcp.tool()
def rename_function_by_address(function_address: str, new_name: str) -> str:
    """
    Rename a function by its address.
    """
    return safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})

@mcp.tool()
def set_function_prototype(function_address: str, prototype: str) -> str:
    """
    Set a function's prototype.
    """
    return safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})

@mcp.tool()
def set_local_variable_type(function_address: str, variable_name: str, new_type: str) -> str:
    """
    Set a local variable's type.
    """
    return safe_post("set_local_variable_type", {"function_address": function_address, "variable_name": variable_name, "new_type": new_type})

@mcp.tool()
def get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified address (xref to).
    
    Args:
        address: Target address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified address
    """
    return safe_get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references from the specified address (xref from).
    
    Args:
        address: Source address in hex format (e.g. "0x1400010a0")
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references from the specified address
    """
    return safe_get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

@mcp.tool()
def get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """
    Get all references to the specified function by name.
    
    Args:
        name: Function name to search for
        offset: Pagination offset (default: 0)
        limit: Maximum number of references to return (default: 100)
        
    Returns:
        List of references to the specified function
    """
    return safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

@mcp.tool()
def list_strings(offset: int = 0, limit: int = 2000, filter: str = None) -> list:
    """
    List all defined strings in the program with their addresses.
    
    Args:
        offset: Pagination offset (default: 0)
        limit: Maximum number of strings to return (default: 2000)
        filter: Optional filter to match within string content
        
    Returns:
        List of strings with their addresses
    """
    params = {"offset": offset, "limit": limit}
    if filter:
        params["filter"] = filter
    return safe_get("strings", params)

###################### [Custom Tools by Team-TOOR] ######################

@mcp.tool()
def get_address_by_symbol_name(symbol_name: str) -> int|None:
    """
    심볼 이름으로 주소를 가져옵니다.
    
    Args:
        symbol_name: 심볼 이름
        
    Returns:
        Address as an integer, or None if not found
        심볼의 이름이 중복되는 경우, 전부 반환됩니다. (type으로 구분 가능)
    """
    params = {"symbol_name": symbol_name}
    return safe_get("get_address_by_symbol_name", params)

@mcp.tool()
def get_all_symbols(index: int = 0, limit: int = 100) -> list:
    """
    모든 심볼 및 주소를 가져옵니다.
    
    Args:
        index: 조회 시작 인덱스 # default: 0
        limit: 최대 조회 개수 # default: 100
        
    Returns:
        List of symbols with their addresses
    """
    params = {"index": index, "limit": limit}
    return safe_get("all_symbols", params)

## Struct 관련 툴 ##

@mcp.tool()
def set_struct_packing(struct_name: str, enable_packing: bool, pack_value: int = None,
                       min_alignment: int = None, machine_aligned: bool = None, repack_now: bool = False) -> str:
    """
    구조체의 패킹 모드를 설정합니다.
    
    Args:
        struct_name: 구조체 이름
        enable_packing: 패킹 모드 활성화 여부
        pack_value: 명시적 패킹 값 (1,2,4,8,16…), None이면 유지
        min_alignment: 최소 정렬 값, None이면 유지
        machine_aligned: MachineAligned 여부, None이면 유지
        repack_now: 즉시 재패킹(repack) 수행 여부 (default: False)
    Returns:
        결과 메시지
    """
    params = {
        "structName": struct_name,
        "enablePacking": enable_packing,
        "packValue": pack_value,
        "minAlignment": min_alignment,
        "machineAligned": machine_aligned,
        "repackNow": repack_now
    }
    return safe_get("set_struct_packing", params)

@mcp.tool()
def add_or_update_struct_member(struct_name: str, member_name: str, member_type: str,
                                offset: int = None, comment: str = None, repack_now: bool = False) -> str:
    """
    구조체의 멤버를 추가/수정합니다.
    Args:
        struct_name: 구조체 이름
        member_name: 멤버 이름
        member_type: 멤버 타입 (예: "u32", "char*", "MyOtherStruct*", ...)
        offset: 구조체 내 오프셋 (기본 None이면 맨 뒤 추가)
        comment: 멤버에 대한 주석 (기본 None)
        repack_now: 즉시 재패킹(repack) 수행 여부 (default: False)
    Returns:
        추가/수정 후 구조체 이름 및 멤버 요약 정보
    """
    params = {
        "structName": struct_name,
        "fieldName": member_name,
        "fieldTypeStr": member_type,
        "offset": offset if offset is not None else -1,
        "comment": comment if comment is not None else "",
        "repackNow": repack_now
    }
    return safe_get("add_or_update_struct_member", params)

@mcp.tool()
def get_structure_info(struct_name: str) -> bool:
    """
    구조체의 정보를 조회합니다..
    Args:
        struct_name: 구조체 이름
    Returns:
        구조체가 존재하면 True, 그렇지 않으면 False
    """
    params = {"structName": struct_name}
    result = safe_get("get_structure_info", params)
    if result and len(result) == 1:
        return result[0].strip().lower() == "true"
    return False

@mcp.tool()
def list_structures(index: int = 0, limit: int = 100) -> str:
    """
    모든 구조체 심볼의 이름을 조회합니다.
    
    Args:
        index: 조회 시작 인덱스  # default: 0
        limit: 최대 조회 개수   # default: 100
        
    Returns:
        List of symbols with their addresses
    """
    params = {"index": index, "limit": limit}
    return safe_get("list_structures", params)

@mcp.tool()
def delete_struct_member(struct_name: str, member_name: str) -> str:
    """
    구조체 멤버를 삭제합니다.
    Args:
        struct_name: 구조체 이름
        member_name: 멤버 이름
    Returns:
        삭제 후 구조체 이름 및 멤버 요약 정보
    """
    params = {"structName": struct_name, "fieldName": member_name}
    return safe_get("delete_struct_member", params)

@mcp.tool()
def delete_structure(struct_name: str) -> str:
    """
    (사용 주의) 구조체 심볼을 통째로 삭제합니다.
    Args:
        struct_name: 구조체 이름
    Returns:
        삭제 성공 여부 메시지
    """
    params = {"structName": struct_name}
    return safe_get("delete_structure", params)


## Union 관련 툴 ##

@mcp.tool()
def set_union_alignment(union_name: str, min_alignment: int, machine_aligned: bool) -> str:
    """
    유니온의 얼라인먼트를 설정합니다.
    
    Args:
        union_name: 유니온 이름
        min_alignment: 최소 정렬 값
        machine_aligned: MachineAligned 여부
    Returns:
        결과 메시지
    """
    params = {
        "unionName": union_name,
        "minAlignment": min_alignment,
        "machineAligned": machine_aligned
    }
    return safe_get("set_union_alignment", params)

@mcp.tool()
def add_or_update_union_member(union_name: str, fileld_type_str: str, filed_name: str) -> str:
    """
    유니온의 멤버를 추가/수정합니다.
    Args:
        union_name: 유니온 이름
        fileld_type_str: 멤버 타입 문자열
        filed_name: 멤버 이름
    Returns:
        추가/수정 후 유니온 이름 및 멤버 요약 정보
    """    
    params = {
        "unionName": union_name,
        "fieldTypeStr": fileld_type_str,
        "fieldName": filed_name
    }
    return safe_get("add_or_update_union_member", params)

@mcp.tool()
def get_union_info(union_name: str) -> bool:
    """
    유니온의 정보를 조회합니다.
    Args:
        union_name: 유니온 이름
    Returns:
        유니온이 존재하면 True, 그렇지 않으면 False
    """
    params = {"unionName": union_name}
    result = safe_get("get_union_info", params)
    if result and len(result) == 1:
        return result[0].strip().lower() == "true"
    return False

@mcp.tool()
def list_unions(index: int = 0, limit: int = 100) -> str:
    """
    모든 유니온 심볼의 이름을 조회합니다.

    Args:
        index: 조회 시작 인덱스  # default: 0
        limit: 최대 조회 개수   # default: 100

    Returns:
        List of symbols with their addresses
    """
    params = {"index": index, "limit": limit}
    return safe_get("list_unions", params)

@mcp.tool()
def delete_union_member(union_name: str, fileld_type_str: str, filed_name: str) -> str:
    """
    유니온 멤버를 삭제합니다.
    Args:
        union_name: 유니온 이름
        fileld_type_str: 멤버 타입 문자열
        filed_name: 멤버 이름
    Returns:
        삭제 후 유니온 이름 및 멤버 요약 정보
    """
    params = {
        "unionName": union_name,
        "fieldTypeStr": fileld_type_str,
        "fieldName": filed_name
    }
    return safe_get("delete_union_member", params)

@mcp.tool()
def delete_union(union_name: str) -> str:
    """
    (사용 주의) 유니온 심볼을 통째로 삭제합니다.
    Args:
        union_name: 유니온 이름
    Returns:
        삭제 성공 여부 메시지
    """
    params = {"unionName": union_name}
    return safe_get("delete_union", params)

##########################################################################

def main():
    parser = argparse.ArgumentParser(description="MCP server for Ghidra")
    parser.add_argument("--ghidra-server", type=str, default=DEFAULT_GHIDRA_SERVER,
                        help=f"Ghidra server URL, default: {DEFAULT_GHIDRA_SERVER}")
    parser.add_argument("--mcp-host", type=str, default="127.0.0.1",
                        help="Host to run MCP server on (only used for sse), default: 127.0.0.1")
    parser.add_argument("--mcp-port", type=int,
                        help="Port to run MCP server on (only used for sse), default: 8081")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse"],
                        help="Transport protocol for MCP, default: stdio")
    args = parser.parse_args()
    
    # Use the global variable to ensure it's properly updated
    global ghidra_server_url
    if args.ghidra_server:
        ghidra_server_url = args.ghidra_server
    
    if args.transport == "sse":
        try:
            # Set up logging
            log_level = logging.INFO
            logging.basicConfig(level=log_level)
            logging.getLogger().setLevel(log_level)

            # Configure MCP settings
            mcp.settings.log_level = "INFO"
            if args.mcp_host:
                mcp.settings.host = args.mcp_host
            else:
                mcp.settings.host = "127.0.0.1"

            if args.mcp_port:
                mcp.settings.port = args.mcp_port
            else:
                mcp.settings.port = 8081

            logger.info(f"Connecting to Ghidra server at {ghidra_server_url}")
            logger.info(f"Starting MCP server on http://{mcp.settings.host}:{mcp.settings.port}/sse")
            logger.info(f"Using transport: {args.transport}")

            mcp.run(transport="sse")
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        mcp.run()
        
if __name__ == "__main__":
    main()
    