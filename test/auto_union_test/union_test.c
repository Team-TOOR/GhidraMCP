// gcc -O2 -pipe -s union_test.c -o union_test.bin
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// 4바이트 폭에서 타입 퍼닝용 유니온
typedef union {
    uint32_t u32;
    int32_t  i32;
    float    f32;
    unsigned char bytes[4];
} Data4;

// IPv4 표현 테스트용 유니온
typedef union {
    uint32_t     u32;
    unsigned char b[4];
} IPv4;

// 중첩 유니온 + 구조체
typedef union {
    Data4 v;                 // 4바이트 단위 값
    struct {                 // 2x 16-bit 쌍
        uint16_t lo;
        uint16_t hi;
    } halves;
} Duo;

typedef struct {
    char tag[8];
    Duo  duo;                // 내부에 유니온
} Record;

// 더 큰 멤버들이 공존하는 유니온 (정렬/크기 관찰용)
typedef union {
    uint8_t   u8;
    uint32_t  u32;
    uint64_t  u64;
    double    f64;
    char      str[16];
} BigUnion;

/* ----------------- 프린트 도우미 ----------------- */
static void print_data4(const Data4* d) {
    printf("[Data4]\n");
    printf("  as u32: %u\n", d->u32);
    printf("  as i32: %d\n", d->i32);
    printf("  as f32: %.6f\n", d->f32);
    printf("  as bytes: %02X %02X %02X %02X\n", d->bytes[0], d->bytes[1], d->bytes[2], d->bytes[3]);
}

static void print_ipv4(const IPv4* ip) {
    printf("[IPv4]\n");
    printf("  as u32: %u\n", ip->u32);
    printf("  as dotted: %u.%u.%u.%u\n", ip->b[0], ip->b[1], ip->b[2], ip->b[3]);
}

static void print_record(const Record* r) {
    printf("[Record]\n");
    printf("  tag: '%s'\n", r->tag);
    printf("  duo.v.u32: %u\n", r->duo.v.u32);
    printf("  duo.v.f32: %.6f\n", r->duo.v.f32);
    printf("  duo.halves: lo=%u hi=%u\n", r->duo.halves.lo, r->duo.halves.hi);
}

static void print_bigunion(const BigUnion* bu) {
    printf("[BigUnion]\n");
    printf("  (sizes) sizeof(BigUnion)=%zu\n", sizeof(BigUnion));
    printf("  as u8 : %u\n", (unsigned)bu->u8);
    printf("  as u32: %u\n", bu->u32);
    printf("  as u64: %llu\n", (unsigned long long)bu->u64);
    printf("  as f64: %.6f\n", bu->f64);
    printf("  as str: '");
    for (int i = 0; i < 16; ++i) {
        unsigned char c = (unsigned char)bu->str[i];
        putchar((c >= 32 && c < 127) ? c : '.');
    }
    printf("'\n");
}

/* ----------------- 메인 테스트 ----------------- */
int main(void) {
    printf("=== Union Layout/Behavior Test ===\n\n");

    // 1) Data4: 한 멤버로 쓰고 다른 멤버로 읽기
    Data4 d = {0};
    d.u32 = 0x3F800000u; // IEEE754 1.0f
    printf(">> Data4 after u32=0x3F800000 (should be f32=1.0)\n");
    print_data4(&d);

    d.f32 = 2.5f;
    printf("\n>> Data4 after f32=2.5\n");
    print_data4(&d);

    d.bytes[0] = 0x78; d.bytes[1] = 0x56; d.bytes[2] = 0x34; d.bytes[3] = 0x12; // 리틀엔디안 가정 출력 관찰
    printf("\n>> Data4 after bytes=[78 56 34 12]\n");
    print_data4(&d);

    // 2) IPv4: 숫자/바이트 동시 관찰
    IPv4 ip = {0};
    ip.b[0] = 127; ip.b[1] = 0; ip.b[2] = 0; ip.b[3] = 1;
    printf("\n>> IPv4 set as 127.0.0.1\n");
    print_ipv4(&ip);

    ip.u32 += 1;  // 127.0.0.2가 되는지 확인
    printf("\n>> IPv4 after u32 += 1\n");
    print_ipv4(&ip);

    // 3) Record: 구조체 + 유니온 중첩
    Record rec;
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.tag, "REC-01", 7);
    rec.duo.v.u32 = 0x11223344;
    printf("\n>> Record initial (duo.v.u32=0x11223344)\n");
    print_record(&rec);

    // halves로 접근해서 같은 메모리를 다른 형태로 보기
    rec.duo.halves.lo = 0xABCD;
    rec.duo.halves.hi = 0x1234;
    printf("\n>> Record after halves set (lo=0xABCD hi=0x1234)\n");
    print_record(&rec);

    // f32로 해석
    rec.duo.v.f32 = 123.75f;
    printf("\n>> Record after set f32=123.75\n");
    print_record(&rec);

    // 4) BigUnion: 가장 큰 멤버 크기에 맞춰 사이즈/정렬 확인
    BigUnion bu;
    memset(&bu, 0, sizeof(bu));
    bu.f64 = 3.141592653589793;
    printf("\n>> BigUnion after f64=pi\n");
    print_bigunion(&bu);

    memcpy(bu.str, "Hello, Union!\0\0\0", 16);
    printf("\n>> BigUnion after write str[16]\n");
    print_bigunion(&bu);

    bu.u64 = 0xAABBCCDDEEFF0011ULL;
    printf("\n>> BigUnion after u64=0xAABBCCDDEEFF0011\n");
    print_bigunion(&bu);

    // 5) 유니온 배열/포인터 테스트
    Data4 arr[3];
    memset(arr, 0, sizeof(arr));
    arr[0].i32 = -1;
    arr[1].f32 = 0.5f;
    arr[2].u32 = 0xDEADBEEF;

    printf("\n>> Data4 array test\n");
    for (int i = 0; i < 3; ++i) {
        printf("  [arr[%d]]\n", i);
        print_data4(&arr[i]);
    }

    // 포인터로 접근해서 변경
    Data4* p = &arr[1];
    p->u32 ^= 0x0000FFFFu;
    printf("\n>> After pointer xor on arr[1].u32 ^= 0x0000FFFF\n");
    print_data4(p);

    // 6) 크기/정렬 요약
    printf("\n=== Size/Align Summary ===\n");
    printf("sizeof(Data4)  = %zu\n", sizeof(Data4));
    printf("sizeof(IPv4)   = %zu\n", sizeof(IPv4));
    printf("sizeof(Duo)    = %zu\n", sizeof(Duo));
    printf("sizeof(Record) = %zu\n", sizeof(Record));
    printf("sizeof(BigUnion)= %zu\n", sizeof(BigUnion));

    return 0;
}
