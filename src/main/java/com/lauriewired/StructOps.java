package com.lauriewired;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

// -----------------------------------------------------------
// 신규 추가 기능: 구조체 생성 (by Team-TOOR)
// -----------------------------------------------------------

/**
 * 구조체 조작 유틸 (MCP 호출 친화적)
 * - 구조체 생성/수정/삭제
 * - 멤버 추가/수정/삭제
 * - 패킹/얼라인먼트 설정
 * - 구조체 존재 여부 확인* 
 */
public class StructOps {
    private final TaskMonitor monitor;
    public StructOps(TaskMonitor monitor) {
        // this.dtm = program.getDataTypeManager();
        this.monitor = (monitor != null) ? monitor : TaskMonitor.DUMMY;
    }

    // =========================
    // 0) 공통: 패킹/얼라인먼트 설정
    // =========================
    public String setStructPacking(Program program,
                                   DataTypeManager dtm,
                                   String structName,
                                   boolean enablePacking,
                                   Integer packValue,
                                   Integer minAlignment,
                                   Boolean machineAligned,
                                   boolean repackNow) {
        Objects.requireNonNull(structName, "structName");
        if (program == null) throw new IllegalStateException("No currentProgram");

        int tx = program.startTransaction("setStructPacking: " + structName);
        boolean commit = false;
        try {
            // ✅ getOrCreateStructure는 Structure(StructureDB일 수 있음)를 반환
            Structure s = getOrCreateStructure(dtm, structName);

            // ✅ Structure 인터페이스로 공통 API 사용
            s.setPackingEnabled(enablePacking);
            if (packValue != null && packValue > 0) {
                s.setExplicitPackingValue(packValue);
            }
            if (minAlignment != null && minAlignment > 0) {
                s.setExplicitMinimumAlignment(minAlignment);
            }
            if (machineAligned != null) {
                if (machineAligned) s.setToMachineAligned();
                else s.setToDefaultAligned();
            }
            if (repackNow) {
                s.repack();
            }

            commit = true;
            // ✅ 이미 DB 객체이므로 그대로 요약 반환
            return summarizeStructAsJson(s, "ok", "packing-updated");
        } catch (Throwable t) {
            return summarizeErrorAsJson(structName, null, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 1) 구조체 멤버 추가/수정
     * =========================
     * 인자:
     *  - structName: 구조체 이름
     *  - fieldTypeStr: 추가/수정할 멤버 타입(문자열, 예: "u32", "char*", "MyOtherStruct*", ...)
     *  - fieldName: 멤버 이름
     *  - offset: 구조체 내 오프셋 (기본 -1이면 맨 뒤 추가)
     *
     * 동작:
     *  - 구조체 없으면 생성 후 추가
     *  - 동일 이름 멤버가 있으면 타입 교체(+ offset >=0 이면 그 오프셋으로 재배치)
     *
     * 반환:
     *  - JSON 문자열(구조체 이름 및 멤버 요약)
     */
    public String addOrUpdateStructMember(
        Program program,
        DataTypeManager dtm,
        String structName,
        String fieldTypeStr,
        String fieldName,
        int offset
    ) {
        Objects.requireNonNull(structName, "structName");
        Objects.requireNonNull(fieldTypeStr, "fieldTypeStr");
        Objects.requireNonNull(fieldName, "fieldName");

        int tx = program.startTransaction("addOrUpdateStructMember: " + structName + "." + fieldName);
        boolean commit = false;
        try {
            Structure struct = getOrCreateStructure(dtm, structName);
            DataType fieldType = parseTypeString(dtm, fieldTypeStr);

            DataTypeComponent existing = findComponentByName(struct, fieldName);

            if (existing != null) {
                // 이미 같은 이름의 멤버가 있으면 타입/위치 교체
                if (offset >= 0) {
                    int len = safeLength(fieldType);
                    struct.replaceAtOffset(offset, fieldType, len, fieldName, existing.getComment());
                } else {
                    int idx = existing.getOrdinal(); // 또는 getComponentIndex() (버전별)
                    int len = safeLength(fieldType);
                    struct.replace(idx, fieldType, len, fieldName, existing.getComment());
                }
            } else {
                // 새 필드 추가
                if (offset >= 0) {
                    int len = safeLength(fieldType);
                    struct.replaceAtOffset(offset, fieldType, len, fieldName, null);
                } else {
                    struct.add(fieldType, fieldName, null); // 길이는 타입 기본값 사용
                }
            }

            // 필요하면 재패킹
            // struct.repack();  // 선택

            commit = true;
            return summarizeStructAsJson(struct, "ok", null);  // ✅ 그대로 반환
        } catch (Throwable t) {
            return summarizeErrorAsJson(structName, fieldName, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 2) 구조체 정보 조회
     * =========================
     * 반환: 구조체 정보 JSON, 없으면 에러 JSON
     */
    public String getStructureInfo(DataTypeManager dtm, String structName) {
        Objects.requireNonNull(structName, "structName");
        
        Structure struct = findStructure(dtm, structName);
        if (struct == null) return summarizeErrorAsJson2(structName, null, "has no structure.");

        return summarizeStructAsJson(struct, "ok", null);
    }

    /* =========================
     * 3) 구조체 멤버 삭제
     * =========================
     * 인자:
     *  - structName
     *  - fieldTypeStr(선택적 검증용, null 허용)  ← 요구사항에 "수정할 멤버 변수 타입"이 있었지만,
     *    실제 삭제 기준은 '이름'이 가장 안전하므로, 타입은 존재 시 일치 검증용으로만 사용.
     *  - fieldName
     *
     * 반환:
     *  - JSON 문자열(구조체 이름 및 멤버 요약)
     */
    public String deleteStructMember(Program program, DataTypeManager dtm, String structName, String fieldTypeStr, String fieldName) {
        Objects.requireNonNull(structName, "structName");
        Objects.requireNonNull(fieldName, "fieldName");

        int tx = program.startTransaction("deleteStructMember: " + structName + "." + fieldName);
        boolean commit = false;
        try {
            Structure struct = findStructure(dtm, structName);
            if (struct == null) {
                throw new NoSuchElementException("Structure not found: " + structName);
            }

            DataTypeComponent comp = findComponentByName(struct, fieldName);
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

            // 삭제: index 기반 → 실패 시 offset 기반으로 폴백
            int index = comp.getOrdinal();
            boolean deleted = false;
            try {
                struct.delete(index);           // ✅ 올바른 API
                deleted = true;
            } catch (Exception ignore) {
                // 일부 버전/상황에서 index 매칭이 꼬일 수 있으니 offset 기반 폴백
            }
            if (!deleted) {
                struct.deleteAtOffset(comp.getOffset());
            }

            commit = true;
            return summarizeStructAsJson(struct, "ok", null);
        } catch (Throwable t) {
            return summarizeErrorAsJson(structName, fieldName, t);
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 4) 구조체 삭제
     * =========================
     * 인자: structName
     * 반환: true(삭제) / false(미삭제)
     */
    public boolean deleteStructure(Program program, DataTypeManager dtm, String structName) {
        Objects.requireNonNull(structName, "structName");

        int tx = program.startTransaction("deleteStructure: " + structName);
        boolean commit = false;
        try {
            Structure struct = findStructure(dtm, structName);
            if (struct == null) {
                return false; // 요구사항상: 없는 경우 false
            }
            boolean removed = dtm.remove(struct, TaskMonitor.DUMMY);
            commit = removed;
            return removed;
        } catch (Throwable t) {
            // 삭제 실패 시 false
            // println("[deleteStructure] " + t.getClass().getSimpleName() + ": " + t.getMessage());
            return false;
        } finally {
            program.endTransaction(tx, commit);
        }
    }

    /* =========================
     * 5) 모든 구조체 조회
     * =========================
     * DataTypeManager에 등록된 모든 Structure를 나열한다.
     * @param dtm          DataTypeManager
     * @param startIndex   0 기반 시작 인덱스 (음수면 0으로 처리)
     * @param limit        최대 조회 개수 (0 또는 음수면 전체)
     * @return JSON 문자열
     */
    public String listAllStructures(DataTypeManager dtm, int startIndex, int limit) {
        Objects.requireNonNull(dtm, "dtm");
        if (startIndex < 0) startIndex = 0;
        if (limit <= 0) limit = Integer.MAX_VALUE;

        // 모든 구조체 수집
        List<Structure> allStructs = new ArrayList<>();
        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext();) {
            DataType dt = it.next();
            if (dt instanceof Structure) {
                allStructs.add((Structure) dt);
            }
        }

        int total = allStructs.size();
        int end = Math.min(startIndex + limit, total);

        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        // sb.append("\"status\":\"ok\",");
        // sb.append("\"total\":").append(total).append(",");
        // sb.append("\"startIndex\":").append(startIndex).append(",");
        // sb.append("\"count\":").append(end - startIndex).append(",");
        // sb.append("\"structures\":[");

        for (int i = startIndex; i < end; i++) {
            Structure s = allStructs.get(i);
            // if (i > startIndex) sb.append(",");
            // sb.append("{");
            // sb.append("\"index\":").append(i).append(",");
            // sb.append("\"name\":\"").append(escape(s.getName())).append("\",");
            // sb.append("\"category\":\"").append(escape(s.getCategoryPath().getPath())).append("\",");
            // sb.append("\"length\":").append(s.getLength()).append(",");
            // sb.append("\"memberCount\":").append(s.getNumComponents()).append(",");
            // sb.append("\"isDefaultCategory\":").append(defCat.equals(s.getCategoryPath()));
            // sb.append("}");
            sb.append(summarizeStructAsJson(s, "ok", null));
            if (i < end - 1)
                sb.append(",\n");
        }

        // sb.append("]}");
        sb.append("\n]");
        return sb.toString();
    }

    /* =========================
     * 내부 유틸
     * ========================= */

    private CategoryPath defaultCategory() {
        return new CategoryPath("/MCP");
    }

    /** DataType 길이 안전 취득: 가변형/미정 길이 예외 대비 */
    private static int safeLength(DataType dt) {
        try {
            int len = dt.getLength();
            // 일부 타입은 0 또는 -1일 수 있음 → 구조체 API는 양수 요구하는 경우가 있어 기본값 보정
            return (len > 0) ? len : 1;
        } catch (Exception e) {
            return 1;
        }
    }

    /** 
     * 구조체를 얻거나 없으면 생성한다.
     * - 우선 default 카테고리에서 정확 매칭을 찾고,
     * - 없으면 전체에서 정확 매칭(있다면 default 우선)을 찾고,
     * - 그래도 없으면 새로 만들고 resolve 결과(보통 StructureDB)를 반환한다.
     */
    private Structure getOrCreateStructure(DataTypeManager dtm, String structName) {
        Objects.requireNonNull(dtm, "dtm");
        Objects.requireNonNull(structName, "structName");

        // 1) default 카테고리에서 정확 매칭 먼저 시도
        DataType dt = dtm.getDataType(defaultCategory(), structName);
        if (dt != null) {
            if (dt instanceof Structure) return (Structure) dt;
            throw new IllegalStateException("A DataType named '" + structName +
                    "' exists in " + defaultCategory() + " but is not a Structure: " + dt.getClass().getSimpleName());
        }

        // 2) 전체에서 이름 정확 매칭(가능하면 default 카테고리를 우선)
        Structure found = findStructure(dtm, structName);
        if (found != null) return found;

        // 3) 없으면 생성 → resolve 결과를 Structure로 사용 (StructureDB일 수 있음)
        StructureDataType created = new StructureDataType(defaultCategory(), structName, 0);
        DataType resolved = dtm.resolve(created, DataTypeConflictHandler.REPLACE_HANDLER);
        if (!(resolved instanceof Structure)) {
            throw new IllegalStateException("Resolved DataType is not a Structure: " +
                    (resolved == null ? "null" : resolved.getClass().getName()));
        }
        return (Structure) resolved;
    }

    /**
     * 이름으로 구조체 찾기.
     * - 정확 일치 우선, 여러 개면 default 카테고리 것을 우선 반환
     * - 없으면 대소문자 무시 일치 중 동일한 우선순위 규칙
     */
    private Structure findStructure(DataTypeManager dtm, String structName) {
        Objects.requireNonNull(dtm, "dtm");
        Objects.requireNonNull(structName, "structName");

        CategoryPath defCat = defaultCategory();
        Structure exactInDefault = null;
        Structure exactAny = null;
        Structure ciInDefault = null;
        Structure ciAny = null;

        for (Iterator<DataType> it = dtm.getAllDataTypes(); it.hasNext();) {
            DataType dt = it.next();
            if (!(dt instanceof Structure)) continue;

            String name = dt.getName();
            CategoryPath cat = dt.getCategoryPath();
            Structure asStruct = (Structure) dt;

            if (name.equals(structName)) {
                if (defCat.equals(cat)) {
                    // 최우선 후보
                    exactInDefault = asStruct;
                    break; // 더 볼 필요 없음
                }
                if (exactAny == null) exactAny = asStruct;
                continue;
            }

            if (ciAny == null && name.equalsIgnoreCase(structName)) {
                if (defCat.equals(cat)) {
                    ciInDefault = asStruct;
                } else if (ciAny == null) {
                    ciAny = asStruct;
                }
            }
        }

        if (exactInDefault != null) return exactInDefault;
        if (exactAny != null) return exactAny;
        if (ciInDefault != null) return ciInDefault;
        return ciAny; // 없으면 null
    }

    /** 필드 이름으로 컴포넌트 찾기 (null-safe, 선택적으로 대소문자 무시 지원 가능) */
    private DataTypeComponent findComponentByName(Structure struct, String fieldName) {
        Objects.requireNonNull(struct, "struct");
        Objects.requireNonNull(fieldName, "fieldName");
        for (DataTypeComponent c : struct.getComponents()) {
            String fn = c.getFieldName();
            if (fn != null && fn.equals(fieldName)) {
                return c;
            }
            // 필요하면 여기도 대소문자 무시 비교를 추가:
            // if (fn != null && fn.equalsIgnoreCase(fieldName)) return c;
        }
        return null;
    }

    /** 간단 타입 파서: "u32", "i64", "char*", "MyStruct*", "double[8]" 같은 케이스 처리 */
    private DataType parseTypeString(DataTypeManager dtm, String typeStr) {
        String s = typeStr.trim();
        // 배열 표기는 멤버 정의에서 처리하는게 일반적이지만, 타입쪽에 들어와도 최소 지원
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

    // Iterator -> Iterable 래퍼 (for-each 가능하게)
    private static <T> Iterable<T> asIterable(final Iterator<T> it) {
        return new Iterable<T>() {
            @Override public Iterator<T> iterator() { return it; }
        };
    }

    /** 기본 타입 매핑 + 사용자 정의 타입 조회 (버전 호환) */
    private DataType mapBaseType(DataTypeManager dtm, String base) {
        String b = base.toLowerCase(java.util.Locale.ROOT);
        switch (b) {
            // ---- 8-bit ----
            case "char":
                return CharDataType.dataType;
            
            case "u8":
            case "uint8":
            case "uchar":
            case "unsignedchar":
                return UnsignedCharDataType.dataType;

                case "schar":
            case "signedchar":
                return SignedCharDataType.dataType;

            case "byte":
            case "i8":
            case "int8":
                return ByteDataType.dataType;

            // ---- 16-bit ----
            case "u16":
            case "uint16":
            case "word":
            case "ushort":
                return UnsignedShortDataType.dataType;   // 표준 16-bit unsigned

            case "i16":
            case "int16":
            case "short":
                return ShortDataType.dataType;           // 표준 16-bit signed

            // ---- 32-bit ----
            case "u32":
            case "uint32":
            case "dword":
            case "uint":
            case "unsigned":
                return UnsignedIntegerDataType.dataType;

            case "i32":
            case "int32":
            case "int":
                return IntegerDataType.dataType;

            // ---- 64-bit ----
            case "u64":
            case "uint64":
            case "qword":
            case "ulonglong":
            case "uquad":
                return UnsignedLongLongDataType.dataType;

            case "i64":
            case "int64":
            case "longlong":
                return LongLongDataType.dataType;

            // ---- 기타 ----
            case "bool":
            case "boolean":
                return BooleanDataType.dataType;

            case "float":
                return FloatDataType.dataType;

            case "double":
                return DoubleDataType.dataType;

            case "wstring":
            case "cwchar":
            case "wchar":
                return WideCharDataType.dataType;

            case "cstring":
            case "string":
                // 실제 C-string은 "char*" 로 표기하도록 유도
                return CharDataType.dataType;
        }

        // 사용자 정의 타입 탐색(카테고리 무시, 완전일치 우선)
        Iterator<DataType> it1 = dtm.getAllDataTypes();
        while (it1.hasNext()) {
            DataType dt = it1.next();
            if (dt.getName().equals(base)) {
                return dt;
            }
        }
        // 대소문자 무시 후보
        Iterator<DataType> it2 = dtm.getAllDataTypes();
        while (it2.hasNext()) {
            DataType dt = it2.next();
            if (dt.getName().equalsIgnoreCase(base)) {
                return dt;
            }
        }

        throw new IllegalArgumentException("Unknown type: '" + base + "'");
    }

    private String normalizeTypeName(DataType dt) {
        if (dt == null) return "null";
        return dt.getDisplayName(); // 포인터/배열 표기 포함된 사람 친화명
    }

    /* ---------- 결과 JSON ---------- */

    private String summarizeStructAsJson(Structure s, String status, String message) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"status\":\"").append(escape(status)).append("\",");
        if (message != null) {
            sb.append("\"message\":\"").append(escape(message)).append("\",");
        }
        sb.append("\"struct\":\"").append(escape(s.getName())).append("\",");
        sb.append("\"size\":").append(s.getLength()).append(",");
        sb.append("\"members\":[");
        DataTypeComponent[] comps = s.getComponents();
        for (int i = 0; i < comps.length; i++) {
            DataTypeComponent c = comps[i];
            if (i > 0) sb.append(",");
            sb.append("{")
              .append("\"index\":").append(c.getOrdinal()).append(",")
              .append("\"offset\":").append(c.getOffset()).append(",")
              .append("\"name\":\"").append(escape(nullToEmpty(c.getFieldName()))).append("\",")
              .append("\"type\":\"").append(escape(normalizeTypeName(c.getDataType()))).append("\",")
              .append("\"length\":").append(c.getLength())
              .append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String summarizeErrorAsJson(String structName, String fieldName, Throwable t) {
        String msg = (t.getClass().getSimpleName() + ": " + (t.getMessage() == null ? "" : t.getMessage()));
        return "{"
            + "\"status\":\"error\","
            + "\"struct\":\"" + escape(nullToEmpty(structName)) + "\","
            + "\"field\":\""  + escape(nullToEmpty(fieldName)) + "\","
            + "\"message\":\"" + escape(msg) + "\""
            + "}";
    }

    private String summarizeErrorAsJson2(String structName, String fieldName, String msg) {
        return "{"
            + "\"status\":\"error\","
            + "\"struct\":\"" + escape(nullToEmpty(structName)) + "\","
            + "\"field\":\""  + escape(nullToEmpty(fieldName)) + "\","
            + "\"message\":\"" + escape(msg) + "\""
            + "}";
    }

    private static String nullToEmpty(String s) { return s == null ? "" : s; }
    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

}
