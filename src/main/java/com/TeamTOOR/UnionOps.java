// UnionOps.java
package com.TeamTOOR;

import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

// -----------------------------------------------------------
// 신규 추가 기능: Union 생성 (by Team-TOOR)
// -----------------------------------------------------------

/**
 * Union 조작 유틸 (MCP 호출 친화적)
 * - 유니온 생성/수정/삭제
 * - 멤버 추가/수정/삭제
 * - 정렬(얼라인먼트) 설정
 * - 유니온 존재 여부 확인/조회/목록
 *
 * 주의:
 * - Union은 Structure와 달리 'offset' 개념이 없고, packing 설정이 없습니다.
 * - 공통 Composite API(최소 정렬, 머신 정렬/기본 정렬)만 지원합니다.
 */
public class UnionOps {
    private final TaskMonitor monitor;
    public UnionOps(TaskMonitor monitor) {
        this.monitor = (monitor != null) ? monitor : TaskMonitor.DUMMY;
    }

    // =========================
    // 0) 공통: 정렬(얼라인먼트) 설정
    // =========================
    public String setUnionAlignment(Program program,
                                    DataTypeManager dtm,
                                    String unionName,
                                    Integer minAlignment,
                                    Boolean machineAligned) {
        Objects.requireNonNull(unionName, "unionName");
        if (program == null) throw new IllegalStateException("No currentProgram");

        int tx = program.startTransaction("setUnionAlignment: " + unionName);
        boolean commit = false;
        try {
            Union u = getOrCreateUnion(dtm, unionName);

            // ✅ Union은 packing이 없으므로 최소 정렬/머신 정렬만 반영
            if (minAlignment != null && minAlignment > 0) {
                u.setExplicitMinimumAlignment(minAlignment);
            }
            if (machineAligned != null) {
                if (machineAligned) u.setToMachineAligned();
                else u.setToDefaultAligned();
            }

            commit = true;
            return summarizeUnionAsJson(u, "ok", "alignment-updated");
        } catch (Throwable t) {
            return summarizeErrorAsJson(unionName, null, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 1) 유니온 멤버 추가/수정
     * =========================
     * 인자:
     *  - unionName: 유니온 이름
     *  - fieldTypeStr: 추가/수정할 멤버 타입 문자열 ("u32","char*","MyStruct*",...)
     *  - fieldName: 멤버 이름
     *
     * 동작:
     *  - 유니온 없으면 생성 후 추가
     *  - 동일 이름 멤버가 있으면 타입 교체 (이름은 유지/변경 가능)
     *
     * 반환: JSON 문자열(유니온 요약)
     */
    public String addOrUpdateUnionMember(
        Program program,
        DataTypeManager dtm,
        String unionName,
        String fieldTypeStr,
        String fieldName
    ) {
        Objects.requireNonNull(unionName, "unionName");
        Objects.requireNonNull(fieldTypeStr, "fieldTypeStr");
        Objects.requireNonNull(fieldName, "fieldName");
    
        int tx = program.startTransaction("addOrUpdateUnionMember: " + unionName + "." + fieldName);
        boolean commit = false;
        try {
            Union u = getOrCreateUnion(dtm, unionName);
            DataType fieldType = parseTypeString(dtm, fieldTypeStr);
        
            DataTypeComponent existing = findComponentByName(u, fieldName);
            if (existing != null) {
                // Union에는 replace(...) 시그니처가 없음 → 삭제 후 재추가로 교체
                String prevComment = existing.getComment();
                int idx = existing.getOrdinal();
                u.delete(idx);
                u.add(fieldType, fieldName, prevComment);
            } else {
                // 새 멤버 추가
                u.add(fieldType, fieldName, null);
            }
        
            commit = true;
            return summarizeUnionAsJson(u, "ok", null);
        } catch (Throwable t) {
            return summarizeErrorAsJson(unionName, fieldName, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 2) 유니온 정보 조회
     * =========================
     * 반환: 유니온 정보 JSON, 없으면 에러 JSON
     */
    public String getUnionInfo(DataTypeManager dtm, String unionName) {
        Objects.requireNonNull(unionName, "unionName");

        Union u = findUnion(dtm, unionName);
        if (u == null) return summarizeErrorAsJson2(unionName, null, "has no union.");

        return summarizeUnionAsJson(u, "ok", null);
    }

    /* =========================
     * 3) 유니온 멤버 삭제
     * =========================
     * 인자:
     *  - unionName
     *  - fieldTypeStr(선택 검증용, null 허용)
     *  - fieldName
     *
     * 반환: JSON 문자열(유니온 요약)
     */
    public String deleteUnionMember(Program program, DataTypeManager dtm, String unionName, String fieldTypeStr, String fieldName) {
        Objects.requireNonNull(unionName, "unionName");
        Objects.requireNonNull(fieldName, "fieldName");

        int tx = program.startTransaction("deleteUnionMember: " + unionName + "." + fieldName);
        boolean commit = false;
        try {
            Union u = findUnion(dtm, unionName);
            if (u == null) {
                throw new NoSuchElementException("Union not found: " + unionName);
            }

            DataTypeComponent comp = findComponentByName(u, fieldName);
            if (comp == null) {
                throw new NoSuchElementException("Field not found: " + fieldName);
            }

            // 타입 검증(요청이 준 경우에만)
            if (fieldTypeStr != null && !fieldTypeStr.isBlank()) {
                DataType expect = parseTypeString(dtm, fieldTypeStr);
                String a = normalizeTypeName(comp.getDataType());
                String b = normalizeTypeName(expect);
                if (!a.equals(b)) {
                    throw new IllegalStateException("Type mismatch: field=" + a + " vs request=" + b);
                }
            }

            // 삭제: index 기반
            int index = comp.getOrdinal();
            u.delete(index);

            commit = true;
            return summarizeUnionAsJson(u, "ok", null);
        } catch (Throwable t) {
            return summarizeErrorAsJson(unionName, fieldName, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 4) 유니온 삭제
     * =========================
     * 인자: unionName
     * 반환: true(삭제) / false(미삭제)
     */
    public boolean deleteUnion(Program program, DataTypeManager dtm, String unionName) {
        Objects.requireNonNull(unionName, "unionName");

        int tx = program.startTransaction("deleteUnion: " + unionName);
        boolean commit = false;
        try {
            Union u = findUnion(dtm, unionName);
            if (u == null) {
                return false;
            }
            boolean removed = dtm.remove(u, TaskMonitor.DUMMY);
            commit = removed;
            return removed;
        } catch (Throwable t) {
            return false;
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 5) 모든 유니온 조회 (페이징)
     * =========================
     * @param dtm          DataTypeManager
     * @param startIndex   0 기반 시작 인덱스 (음수면 0)
     * @param limit        최대 조회 개수 (0/음수 -> 전체)
     * @return JSON 배열 문자열
     */
    public String listAllUnions(DataTypeManager dtm, int startIndex, int limit) {
        Objects.requireNonNull(dtm, "dtm");
        if (startIndex < 0) startIndex = 0;
        if (limit <= 0) limit = Integer.MAX_VALUE;

        List<Union> allUnions = new ArrayList<>();
        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext();) {
            DataType dt = it.next();
            if (dt instanceof Union) {
                allUnions.add((Union) dt);
            }
        }

        int total = allUnions.size();
        int end = Math.min(startIndex + limit, total);

        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = startIndex; i < end; i++) {
            Union u = allUnions.get(i);
            sb.append(summarizeUnionAsJson(u, "ok", null));
            if (i < end - 1) sb.append(",\n");
        }
        sb.append("\n]");
        return sb.toString();
    }

    /* =========================
     * 내부 유틸
     * ========================= */

    private CategoryPath defaultCategory() {
        return new CategoryPath("/MCP");
    }

    /** DataType 길이 안전 취득 */
    private static int safeLength(DataType dt) {
        try {
            int len = dt.getLength();
            return (len > 0) ? len : 1;
        } catch (Exception e) {
            return 1;
        }
    }

    /** 유니온을 얻거나 없으면 생성한다. */
    private Union getOrCreateUnion(DataTypeManager dtm, String unionName) {
        Objects.requireNonNull(dtm, "dtm");
        Objects.requireNonNull(unionName, "unionName");

        // 1) default 카테고리에서 정확 매칭
        DataType dt = dtm.getDataType(defaultCategory(), unionName);
        if (dt != null) {
            if (dt instanceof Union) return (Union) dt;
            throw new IllegalStateException("A DataType named '" + unionName +
                    "' exists in " + defaultCategory() + " but is not a Union: " + dt.getClass().getSimpleName());
        }

        // 2) 전체에서 이름 정확/대소문자 무시 매칭
        Union found = findUnion(dtm, unionName);
        if (found != null) return found;

        // 3) 없으면 생성 → resolve 결과 사용
        UnionDataType created = new UnionDataType(defaultCategory(), unionName);
        DataType resolved = dtm.resolve(created, DataTypeConflictHandler.REPLACE_HANDLER);
        if (!(resolved instanceof Union)) {
            throw new IllegalStateException("Resolved DataType is not a Union: " +
                    (resolved == null ? "null" : resolved.getClass().getName()));
        }
        return (Union) resolved;
    }

    /** 이름으로 유니온 찾기 (default 카테고리 우선) */
    private Union findUnion(DataTypeManager dtm, String unionName) {
        Objects.requireNonNull(dtm, "dtm");
        Objects.requireNonNull(unionName, "unionName");

        CategoryPath defCat = defaultCategory();
        Union exactInDefault = null;
        Union exactAny = null;
        Union ciInDefault = null;
        Union ciAny = null;

        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext();) {
            DataType dt = it.next();
            if (!(dt instanceof Union)) continue;

            String name = dt.getName();
            CategoryPath cat = dt.getCategoryPath();
            Union asUnion = (Union) dt;

            if (name.equals(unionName)) {
                if (defCat.equals(cat)) {
                    exactInDefault = asUnion;
                    break;
                }
                if (exactAny == null) exactAny = asUnion;
                continue;
            }

            if (ciAny == null && name.equalsIgnoreCase(unionName)) {
                if (defCat.equals(cat)) ciInDefault = asUnion;
                else if (ciAny == null) ciAny = asUnion;
            }
        }

        if (exactInDefault != null) return exactInDefault;
        if (exactAny != null) return exactAny;
        if (ciInDefault != null) return ciInDefault;
        return ciAny;
    }

    /** 필드 이름으로 컴포넌트 찾기 (Union 전용) */
    private DataTypeComponent findComponentByName(Union u, String fieldName) {
        Objects.requireNonNull(u, "union");
        Objects.requireNonNull(fieldName, "fieldName");
        for (DataTypeComponent c : u.getComponents()) {
            String fn = c.getFieldName();
            if (fn != null && fn.equals(fieldName)) {
                return c;
            }
            // 필요 시 대소문자 무시 비교 가능:
            // if (fn != null && fn.equalsIgnoreCase(fieldName)) return c;
        }
        return null;
    }

    /** 간단 타입 파서: "u32", "i64", "char*", "MyStruct*", "double[8]" 등 */
    private DataType parseTypeString(DataTypeManager dtm, String typeStr) {
        String s = typeStr.trim();
        Integer arrayLen = null;
        int lb = s.indexOf('[');
        if (lb >= 0 && s.endsWith("]")) {
            String n = s.substring(lb + 1, s.length() - 1).trim();
            arrayLen = Integer.parseInt(n);
            s = s.substring(0, lb).trim();
        }

        // 포인터 깊이(*)
        int stars = 0;
        while (s.endsWith("*")) {
            stars++;
            s = s.substring(0, s.length() - 1).trim();
        }

        DataType base = mapBaseType(dtm, s);
        DataType dt = base;

        for (int i = 0; i < stars; i++) {
            dt = new PointerDataType(dt, dtm);
        }

        if (arrayLen != null && arrayLen > 0) {
            dt = new ArrayDataType(dt, arrayLen, Math.max(1, dt.getLength()));
        }
        return dt;
    }

    /** 기본 타입 매핑 + 사용자 정의 타입 조회 */
    private DataType mapBaseType(DataTypeManager dtm, String base) {
        String b = base.toLowerCase(java.util.Locale.ROOT);
        switch (b) {
            // ---- 8-bit ----
            case "char": return CharDataType.dataType;
            case "u8":
            case "uint8":
            case "uchar":
            case "unsignedchar": return UnsignedCharDataType.dataType;
            case "schar":
            case "signedchar": return SignedCharDataType.dataType;
            case "byte":
            case "i8":
            case "int8": return ByteDataType.dataType;

            // ---- 16-bit ----
            case "u16":
            case "uint16":
            case "word":
            case "ushort": return UnsignedShortDataType.dataType;
            case "i16":
            case "int16":
            case "short": return ShortDataType.dataType;

            // ---- 32-bit ----
            case "u32":
            case "uint32":
            case "dword":
            case "uint":
            case "unsigned": return UnsignedIntegerDataType.dataType;
            case "i32":
            case "int32":
            case "int": return IntegerDataType.dataType;

            // ---- 64-bit ----
            case "u64":
            case "uint64":
            case "qword":
            case "ulonglong":
            case "uquad": return UnsignedLongLongDataType.dataType;
            case "i64":
            case "int64":
            case "longlong": return LongLongDataType.dataType;

            // ---- 기타 ----
            case "bool":
            case "boolean": return BooleanDataType.dataType;
            case "float": return FloatDataType.dataType;
            case "double": return DoubleDataType.dataType;
            case "wstring":
            case "cwchar":
            case "wchar": return WideCharDataType.dataType;
            case "cstring":
            case "string": return CharDataType.dataType; // 실제 C-string은 "char*" 권장
        }

        // 사용자 정의 타입 탐색(완전일치 → 대소문자 무시)
        Iterator<DataType> it1 = dtm.getAllDataTypes();
        while (it1.hasNext()) {
            DataType dt = it1.next();
            if (dt.getName().equals(base)) return dt;
        }
        Iterator<DataType> it2 = dtm.getAllDataTypes();
        while (it2.hasNext()) {
            DataType dt = it2.next();
            if (dt.getName().equalsIgnoreCase(base)) return dt;
        }
        throw new IllegalArgumentException("Unknown type: '" + base + "'");
    }

    private String normalizeTypeName(DataType dt) {
        if (dt == null) return "null";
        return dt.getDisplayName();
    }

    /* ---------- 결과 JSON ---------- */

    private String summarizeUnionAsJson(Union u, String status, String message) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"status\":\"").append(escape(status)).append("\",");
        if (message != null) {
            sb.append("\"message\":\"").append(escape(message)).append("\",");
        }
        sb.append("\"union\":\"").append(escape(u.getName())).append("\",");
        sb.append("\"size\":").append(u.getLength()).append(",");
        sb.append("\"members\":[");
        DataTypeComponent[] comps = u.getComponents();
        for (int i = 0; i < comps.length; i++) {
            DataTypeComponent c = comps[i];
            if (i > 0) sb.append(",");
            sb.append("{")
              .append("\"index\":").append(c.getOrdinal()).append(",")
              .append("\"name\":\"").append(escape(nullToEmpty(c.getFieldName()))).append("\",")
              .append("\"type\":\"").append(escape(normalizeTypeName(c.getDataType()))).append("\",")
              .append("\"length\":").append(c.getLength())
              .append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String summarizeErrorAsJson(String unionName, String fieldName, Throwable t) {
        String msg = (t.getClass().getSimpleName() + ": " + (t.getMessage() == null ? "" : t.getMessage()));
        return "{"
            + "\"status\":\"error\","
            + "\"union\":\"" + escape(nullToEmpty(unionName)) + "\","
            + "\"field\":\""  + escape(nullToEmpty(fieldName)) + "\","
            + "\"message\":\"" + escape(msg) + "\""
            + "}";
    }

    private String summarizeErrorAsJson2(String unionName, String fieldName, String msg) {
        return "{"
            + "\"status\":\"error\","
            + "\"union\":\"" + escape(nullToEmpty(unionName)) + "\","
            + "\"field\":\""  + escape(nullToEmpty(fieldName)) + "\","
            + "\"message\":\"" + escape(msg) + "\""
            + "}";
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }
    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
