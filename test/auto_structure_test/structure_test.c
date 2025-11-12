// gcc -O2 -pipe -s structure_test.c -o structure_test.bin
#include <stdio.h>
#include <string.h>

// 구조체 정의
typedef struct {
    int id;
    float score;
    char name[32];
} Student;

// 중첩 구조체
typedef struct {
    char course_name[32];
    int credit;
    Student student;
} Course;

// 함수: 구조체 초기화 및 출력
void print_student(const Student* s) {
    printf("[Student]\n");
    printf("  ID: %d\n", s->id);
    printf("  Name: %s\n", s->name);
    printf("  Score: %.2f\n", s->score);
}

void print_course(const Course* c) {
    printf("[Course]\n");
    printf("  Course: %s\n", c->course_name);
    printf("  Credit: %d\n", c->credit);
    print_student(&c->student);
}

int main(void) {
    // 구조체 변수 선언 및 초기화
    Student s1 = {1001, 95.5f, "Alice"};
    Course c1;

    strcpy(c1.course_name, "Computer Science");
    c1.credit = 3;
    c1.student = s1; // 구조체 복사

    // 출력
    print_student(&s1);
    printf("\n");
    print_course(&c1);

    // 포인터 접근 테스트
    Student* ps = &s1;
    ps->score += 2.5f;
    printf("\n[Updated]\n");
    print_student(ps);

    return 0;
}
