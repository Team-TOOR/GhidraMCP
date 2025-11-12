[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/releases)
[![GitHub stars](https://img.shields.io/github/stars/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/LaurieWired/GhidraMCP)](https://github.com/LaurieWired/GhidraMCP/graphs/contributors)
[![Follow @lauriewired](https://img.shields.io/twitter/follow/lauriewired?style=social)](https://twitter.com/lauriewired)

![ghidra_MCP_logo](https://github.com/user-attachments/assets/4986d702-be3f-4697-acce-aea55cd79ad3)


# ghidraMCP
ghidraMCP is an Model Context Protocol server for allowing LLMs to autonomously reverse engineer applications. It exposes numerous tools from core Ghidra functionality to MCP clients.

https://github.com/user-attachments/assets/36080514-f227-44bd-af84-78e29ee1d7f9


# Features
MCP Server + Ghidra Plugin

- Decompile and analyze binaries in Ghidra
- Automatically rename methods and data
- List methods, classes, imports, and exports

# Installation

## Prerequisites
- Install [Ghidra](https://ghidra-sre.org)
- Python3
- MCP [SDK](https://github.com/modelcontextprotocol/python-sdk)

## Ghidra
First, download the latest [release](https://github.com/LaurieWired/GhidraMCP/releases) from this repository. This contains the Ghidra plugin and Python MCP client. Then, you can directly import the plugin into Ghidra.

1. Run Ghidra
2. Select `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhidraMCP-1-2.zip` (or your chosen version) from the downloaded release
5. Restart Ghidra
6. Make sure the GhidraMCPPlugin is enabled in `File` -> `Configure` -> `Developer`
7. *Optional*: Configure the port in Ghidra with `Edit` -> `Tool Options` -> `GhidraMCP HTTP Server`

Video Installation Guide:


https://github.com/user-attachments/assets/75f0c176-6da1-48dc-ad96-c182eb4648c3



## MCP Clients

Theoretically, any MCP client should work with ghidraMCP.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a Ghidra MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

Alternatively, edit this file directly:
```
/Users/YOUR_USER/Library/Application Support/Claude/claude_desktop_config.json
```

The server IP and port are configurable and should be set to point to the target Ghidra instance. If not set, both will default to localhost:8080.

## Example 2: Cline
To use GhidraMCP with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
python bridge_mcp_ghidra.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8081 --ghidra-server http://127.0.0.1:8080/
```

The only *required* argument is the transport. If all other arguments are unspecified, they will default to the above. Once the MCP server is running, open up Cline and select `MCP Servers` at the top.

![Cline select](https://github.com/user-attachments/assets/88e1f336-4729-46ee-9b81-53271e9c0ce0)

Then select `Remote Servers` and add the following, ensuring that the url matches the MCP host and port:

1. Server Name: GhidraMCP
2. Server URL: `http://127.0.0.1:8081/sse`

## Example 3: 5ire
Another MCP client that supports multiple models on the backend is [5ire](https://github.com/nanbingxyz/5ire). To set up GhidraMCP, open 5ire and go to `Tools` -> `New` and set the following configurations:

1. Tool Key: ghidra
2. Name: GhidraMCP
3. Command: `python /ABSOLUTE_PATH_TO/bridge_mcp_ghidra.py`

# Building from Source
1. Copy the following files from your Ghidra directory to this project's `lib/` directory:
- `Ghidra/Features/Base/lib/Base.jar`
- `Ghidra/Features/Decompiler/lib/Decompiler.jar`
- `Ghidra/Framework/Docking/lib/Docking.jar`
- `Ghidra/Framework/Generic/lib/Generic.jar`
- `Ghidra/Framework/Project/lib/Project.jar`
- `Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling.jar`
- `Ghidra/Framework/Utility/lib/Utility.jar`
- `Ghidra/Framework/Gui/lib/Gui.jar`
2. Build with Maven by running:

`mvn clean package assembly:single`

The generated zip file includes the built Ghidra plugin and its resources. These files are required for Ghidra to recognize the new extension.

- lib/GhidraMCP.jar
- extensions.properties
- Module.manifest

# Custom Tools
> by Team-TOOR

## 추가된 도구들

### 유틸
- `get_address_by_symbol_name`
  > 25.10.11 update
  - 심볼 이름으로 주소 정보를 가져오는 도구입니다.
  - `GET /get_address_by_symbol_name`
  - 테스트 완료
  - 예시 결과
    ```
    g_whatisthis | type=Function | ns=Global | addr=001014f0 | va=0x1014F0 | rva=0x14F0
    g_whatisthis | type=Label | ns=Global | addr=00102022 | va=0x102022 | rva=0x2022
    ...
    ```

- `get_all_symbols`
  > 25.10.11 update
  - 모든 심볼 및 주소 정보를 가져오는 도구입니다.
  - `GET /all_symbols`
  - 테스트 완료
  - 예시 결과
    ```
    "name":"ElfComment[0]","type":"Label","namespace":"Global","is_primary":true,"address":".comment::00000000","va":"0x0","rva":"0xfffffffffff00000"
    "name":"DAT_.shstrtab__00000000","type":"Label","namespace":"Global","is_primary":true,"address":". shstrtab::00000000", "va":"0x0","rva":"0xfffffffffff00000"
    "name":"Elf64_Shdr_ARRAY__elfSectionHeaders__00000000","type":"Label","namespace":"Global","is_primary":true,   "address":"_elfSectionHeaders::00000000","va":"0x0","rva":"0xfffffffffff00000"
    "name":"Elf64_Phdr_ARRAY_00100040","type":"Label","namespace":"Global","is_primary":true,"address":"00100040",    "va":"0x100040","rva":"0x40"
    ...
    ```

### 구조체 심볼 생성/수정/삭제/조회
- `set_struct_packing`
  > 25.10.16 update
  - 구조체 패킹/얼라인먼트 설정
  - `GET /set_struct_packing`
  - 테스트: `http://localhost:8080/set_struct_packing?structName=MyStruct&enablePacking=true&packValue=4&minAlignment=1&machineAligned=false&repackNow=true`

- `add_or_update_struct_member`
  > 25.10.16 update
  - 구조체 멤버 추가/수정
  - `GET /add_or_update_struct_member`
  - 테스트: `http://localhost:8080/add_or_update_struct_member?structName=MyStruct&fieldTypeStr=int&fieldName=age`

- `get_structure_info`
  > 25.10.16 update
  - 구조체 정보 조회
  - `GET /get_structure_info`
  - 테스트: `http://localhost:8080/get_structure_info?structName=MyStruct`

- `list_structures`
  > 25.10.16 update
  - 모든 구조체 조회
  - `GET /list_structures`
  - 테스트: `http://localhost:8080/list_structures`

- `delete_struct_member`
  > 25.10.16 update
  - 구조체 멤버 삭제
  - `GET /delete_struct_member`
  - 테스트: `http://localhost:8080/delete_struct_member?structName=MyStruct&fieldName=age`

- `delete_structure`
  > 25.10.16 update
  - 구조체 삭제
  - `GET /delete_structure`
  - 테스트: `http://localhost:8080/delete_structure?structName=MyStruct`

### Union 심볼 생성/수정/삭제/조회
- `set_union_alignment`
  > 25.11.13 update
  - 유니온 패킹/얼라인먼트 설정
  - `GET /set_union_alignment`
  - 테스트: `http://localhost:8080/set_union_alignment?unionName=MyUnion&minAlignment=1&machineAligned=false`

- `add_or_update_union_member`
  > 25.11.13 update
  - 유니온 멤버 추가/수정
  - `GET /add_or_update_union_member`
  - 테스트: `http://localhost:8080/add_or_update_union_member?unionName=MyUnion&fieldTypeStr=int&fieldName=value`

- `get_union_info`
  > 25.11.13 update
  - 유니온 정보 조회
  - `GET /get_union_info`
  - 테스트: `http://localhost:8080/get_union_info?unionName=MyUnion`

- `list_unions`
  > 25.11.13 update
  - 모든 유니온 조회
  - `GET /list_unions`
  - 테스트: `http://localhost:8080/list_unions?startIndex=0&limit=100`

- `delete_union_member`
  > 25.11.13 update
  - 유니온 멤버 삭제
  - `GET /delete_union_member`
  - 테스트: `http://localhost:8080/delete_union_member?unionName=MyUnion&fieldName=value`

- `delete_union`
  > 25.11.13 update
  - 유니온 삭제
  - `GET /delete_union`
  - 테스트: `http://localhost:8080/delete_union?unionName=MyUnion`

### Enum 심볼 생성/수정/삭제/조회
> TODO

### 메모리 데이터 조회/수정 (Binary Data Read/Patch)
> TODO
> 하네스 작성을 위한 분기문 조작에 사용할 수 있을 것

### TODO List
[X] 유틸 기능
  [X] 심볼 이름으로 주소 정보 조회 기능
  [X] 모든 심볼 정보 조회 기능
[X] 구조체 심볼 생성/수정/삭제/조회 기능
  [X] 구조체 패킹/얼라인먼트 설정
  [X] 구조체 멤버 추가/수정
  [X] 구조체 정보 조회
  [X] 모든 구조체 조회
  [X] 구조체 멤버 삭제
  [X] 구조체 삭제
[X] 유니온 심볼 생성/수정/삭제/조회 기능
  [X] 유니온 패킹/얼라인먼트 설정
  [X] 유니온 멤버 추가/수정
  [X] 유니온 정보 조회
  [X] 모든 유니온 조회
  [X] 유니온 멤버 삭제
  [X] 유니온 삭제
[ ] Enum 심볼 생성/수정/삭제/조회 기능
[ ] 메모리 데이터 조회/수정 기능 (Binary Data Read/Patch)
[ ] 구조체/유니온/Enum 기능 통합 (최적화)

## 플러그인 빌드 및 테스트 정보
- JDK Version: 21
- maven Version: 3.6.3
  - Build Command: `$ mvn -e -X clean package assembly:single`
- Ghidra Version: 11.4.2 Public

## Trouble Shooting

### Case 1: Ghidra에 Extention을 추가했음에도, GhidraMCP Server가 실행 안되는 경우
- 사전 체크 리스트
  - `Code Browser - Edit - Tool Options`에 `GhidraMCP HTTP Server`가 있는지 확인
- 해결 방법
  - 경우 1. 만약 위 플러그인이 있다면, 포트 번호가 잘 설정되어 있는지 확인해봅니다.
  - 경우 2. 만약 위 플러그인이 없다면 Ghidra의 `CodeBrowser.tcd`가 손상되었을 가능성이 높습니다.
    1. 기존에 설치한(문제가 있는) GhidraMCP 플러그인을 삭제합니다.
    2. Ghidra 프로세스를 종료합니다.
    3. 아래 경로로 이동하여 `CodeBrowser.tcd` 파일을 삭제합니다.
      - 윈도우: `C:\Users\<USER>\AppData\Roaming\ghidra\ghidra_11.4.2_PUBLIC\tools\CodeBrowser.tcd`
        - 또는 `_code_browser.tcd`
      - 리눅스: `~/.ghidra/.ghidra_<버전>/tools/CodeBrowser.tcd`
    4. Ghidra 프로세스를 다시 실행합니다. Ghidra 프로세스 메인 화면에서 아래의 작업을 통해 CodeBrowser 도구를 재설치해줍니다.
      - `Tools -> Import Default Tools -> defaultTools/CodeBrowser.tool 체크 -> OK 버튼 클릭`
    5. 다시 GhidraMCP 플러그인을 설치합니다.

