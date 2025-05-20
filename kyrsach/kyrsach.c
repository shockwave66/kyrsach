#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>


#pragma warning(disable:4996)


bool is_prime(unsigned long long n) {
    if (n < 2) {
        return false;
    }
    for (unsigned long long i = 2; i < n; i++) {
        if (n % i == 0) {
            return false;
        }
    }
    return true;
}


unsigned long long mod_exp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}


bool is_generator(unsigned long long g, unsigned long long p) {
    if (g < 1 || g > p - 1) {
        return false;
    }

    bool* seen = (bool*)calloc(p, sizeof(bool));


    for (unsigned long long k = 1; k < p; k++) {
        unsigned long long result = mod_exp(g, k, p);
        if (seen[result]) {
            free(seen);
            return false;
        }
        seen[result] = true;
    }

    free(seen);
    return true;
}


void encrypt_message(const char* message, unsigned long long p, unsigned long long g,
    unsigned long long y, unsigned long long* c1, unsigned long long* c2) {
    unsigned long long k;
    int i;

    srand(time(NULL));
    int len = strlen(message);
    for (i = 0; i < len; i++) {
        do {
            k = rand() % (p - 2) + 1;
        } while (!is_prime(k));
        c1[i] = mod_exp(g, k, p);
        c2[i] = (mod_exp(y, k, p) * (unsigned long long)message[i]) % p;
    }
}


void decrypt_message(unsigned long long* c1, unsigned long long* c2,
    int len, unsigned long long p, unsigned long long x, char* decrypted_message) {

    int i;

    for (i = 0; i < len; i++) {
        unsigned long long inv = mod_exp(c1[i], p - 1 - x, p);
        decrypted_message[i] = (char)((c2[i] * inv) % p);
    }
    decrypted_message[len] = '\0';
}


void write_encoded_toFile(const char* filename, const unsigned long long* c1, const unsigned long long* c2, int len) {

    int i;
    FILE* file = fopen(filename, "w");
    if (!file) {
        perror("������� �������� ����� ��� ������");
        return;
    }

    // �������� ����������� �����������
    for (i = 0; i < len; i++) {
        fprintf(file, "%llu %llu ", c1[i], c2[i]);
    }

    fclose(file);
}


void write_decoded_toFile(const char* filename, char* message) {
    int i;
    FILE* file = fopen(filename, "w");
    if (!file) {
        perror("������� �������� ����� ��� ������");
        return;
    }

    // �������� ����������� �����������
    fprintf(file, "%s", message);

    fclose(file);

}


void read_encoded_fromFile(const char* filename, unsigned long long* c1, unsigned long long* c2, int* len) {
    int i;

    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("������� �������� ����� ��� ����������");
        return;
    }

    *len = 0;
    while (fscanf(file, "%llu %llu ", &c1[*len], &c2[*len]) == 2) {
        (*len)++;
    }

    fclose(file);
}


void read_decoded_fromFile(const char* filename, char* message, int* len) {
    int i;
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("������� �������� ����� ��� ������");
        return;
    }

    fgets(message, 256, file);
    *len = strlen(message);
    if (message[*len - 1] == '\n') {
        message[*len - 1] = '\0';
        (*len)--;
    }

    fclose(file);
}


void read_encoded_fromConsole(unsigned long long* c1, unsigned long long* c2, int* len) {
    char buffer[256];
    printf("\n������ ��� ����������� �����������:\n");

    while (*len < 128) {
        fgets(buffer, sizeof(buffer), stdin);

        if (buffer[0] == '\n') {
            break;
        }

        if (sscanf(buffer, "%llu %llu", &c1[*len], &c2[*len]) == 2) {
            (*len)++;
        }
        else {
            printf("�������! ������ ��� �����, ������� �������.\n");
        }
    }
}


void read_decoded_fromConsole(char* message, int* len) {
    printf("\n������ ��� ����������� ��� ����������: ");
    scanf("%[^\n]", message);
    *len = strlen(message);
}


void userEncryptionParameters(unsigned long long* p, unsigned long long* g, unsigned long long* x, unsigned long long* y) {

    int user_keyInput_option = -1;
    bool isPrime,
        isGenerator;

    char message[256];

    unsigned long long
        c1[256],
        c2[256];

    printf("��������� �� �������������:\n");
    printf("-- p (������ �����): %llu\n", *p);
    printf("-- g (���������): %llu\n", *g);
    printf("-- x (��������� ����): %llu\n", *x);
    printf("-- y (�������� ����): %llu\n", *y);
    printf("\n�� ��������� ���������������:\n");
    printf("0:  ��������������� ����� ���������\n");
    printf("1:  ��������� �� ������������� \n");
    //while (getchar() != '\n');


    do {
        scanf("%d", &user_keyInput_option);
        if (user_keyInput_option < 0 || user_keyInput_option > 1) {
            printf("������������ ���. �� ���� 0 ��� 1\n");
        }
    } while (user_keyInput_option < 0 || user_keyInput_option > 1);

    // ������������ ��������� ����������
    if (user_keyInput_option == 0) {
        printf("������ ������ ����� p (������ �����): ");
        do {
            scanf_s("%llu", p);
            isPrime = is_prime(*p);
            if (!isPrime) {
                printf("�� �� ������ ����� (107, 109, 113, 229, 337, 401...)!\n");
            }
        } while (!isPrime);

        printf("������ ����� ��������� g (1 < g < p - 1): ");
        do {
            scanf_s("%llu", g);
            isGenerator = is_generator(*g, *p);
            if (!isGenerator || *g > *p - 1) {
                printf("����� �� ��������!\n");
            }
        } while (!isGenerator || *g > *p - 1);

        printf("������ ��������� ���� x (1 < x < p - 2): ");
        do {
            scanf_s("%llu", x);
            if (*x <= 1 || *x >= *p - 2) {
                printf("����� �� ��������!\n");
            }
        } while (*x <= 1 || *x >= *p - 2);
    }

    // �������� ����
    *y = mod_exp(*g, *x, *p);
}


void userDecryptionParameters(unsigned long long* p, unsigned long long* g, unsigned long long* x) {
    int user_keyInput_option = -1;

    bool isPrime,
        isGenerator;

    printf("��������� �� �������������:\n");
    printf("-- p (������ �����): %llu\n", *p);
    printf("-- g (���������): %llu\n", *g);
    printf("-- x (��������� ����): %llu\n", *x);
    printf("\n�� ��������� ���������������:\n");
    printf("0:  ��������������� ����� ���������\n");
    printf("1:  ��������� �� ������������� \n");
    //while (getchar() != '\n');

    do {
        scanf("%d", &user_keyInput_option);
        if (user_keyInput_option < 0 || user_keyInput_option > 1) {
            printf("������������ ���. �� ���� 0 ��� 1\n");
        }
    } while (user_keyInput_option < 0 || user_keyInput_option > 1);

    // ������������ ��������� ����������
    if (user_keyInput_option == 0) {
        printf("������ ������ ����� p (������ �����): ");
        do {
            scanf_s("%llu", p);
            isPrime = is_prime(*p);
            if (!isPrime) {
                printf("�� �� ������ ����� (107, 109, 113, 229, 337, 401...)!\n");
            }
        } while (!isPrime);

        printf("������ ����� ��������� g (1 < g < p - 1): ");
        do {
            scanf_s("%llu", g);
            isGenerator = is_generator(*g, *p);
            if (!isGenerator || *g > *p - 1) {
                printf("����� �� ��������!\n");
            }
        } while (!isGenerator || *g > *p - 1);

        printf("������ ��������� ���� x (1 < x < p - 2): ");
        do {
            scanf_s("%llu", x);
            if (*x <= 1 || *x >= *p - 2) {
                printf("����� �� ��������!\n");
            }
        } while (*x <= 1 || *x >= *p - 2);
    }
}


int main() {

    system("chcp 1251 & cls");

    unsigned long long
        p,              // ������ �����
        g,              // ��������� �����
        x,              // ��������� ����
        y;              // �������� ����
    int read_len = 0,   // ������� ����������� ����������
        i;

    int user_action_option = -1,
        user_dataSource_option = -1;


    char decrypted_message[256];


    while (true) {

        unsigned long long c1[256], c2[256], read_c1[256], read_c2[256];

        p = 257;
        g = 3;
        x = 7;
        y = mod_exp(g, x, p);

        printf("----------- ���������� ���-������ -----------\n");
        printf("������� �������:\n");
        printf("0\t �����\n");
        printf("1\t �����������\n");
        printf("2\t ������������\n");
        printf("��� ������ ���������?\n");

        do {
            scanf("%d", &user_action_option);
            if (user_action_option != 0 && user_action_option != 1 && user_action_option != 2) {
                printf("������� �������\n");
            }
        } while (user_action_option != 0 && user_action_option != 1 && user_action_option != 2);
        while (getchar() != '\n');

        system("cls");
        switch (user_action_option) {
        case 0: { return 0; }
        case 1: { userEncryptionParameters(&p, &g, &x, &y); break; }
        case 2: { userDecryptionParameters(&p, &g, &x); break; }
        }


        system("cls");
        printf("����� ����� ����� ��� ��������?\n");
        printf("0: �����\n");
        printf("1: �������\n");
        printf("2: ����\n");

        do {
            scanf("%d", &user_dataSource_option);
            if (user_dataSource_option != 0 && user_dataSource_option != 1 && user_dataSource_option != 2) {
                printf("������� �������\n");
            }
        } while (user_dataSource_option != 0 && user_dataSource_option != 1 && user_dataSource_option != 2);
        while (getchar() != '\n');

        switch (user_dataSource_option) {
        case 0: { return 0; }
        case 1: {
            if (user_action_option == 1) {
                read_decoded_fromConsole(decrypted_message, &read_len);
                printf("\n������� �����������: %s", decrypted_message);
            }
            else {
                read_encoded_fromConsole(read_c1, read_c2, &read_len);
                printf("\n������� �����������: ");
                for (i = 0; i < read_len; i++) {
                    printf("%llu %llu ", read_c1[i], read_c2[i]);
                }
            }
            break; 
        }
        case 2: {
            if (user_action_option == 1) {
                read_decoded_fromFile("decrypted_message.txt", decrypted_message, &read_len);
                printf("\n�����������:\n%s\n", decrypted_message);
            }
            else {
                read_encoded_fromFile("encrypted_message.txt", read_c1, read_c2, &read_len);
                printf("\n����������� �����������:\n");
                for (i = 0; i < read_len; i++) {
                    printf("%llu %llu ", read_c1[i], read_c2[i]);
                }
                printf("\n");
                break;
            }
        }
        }


        switch (user_action_option) {
        case 0: { return 0; }
        case 1: {
            encrypt_message(decrypted_message, p, g, y, c1, c2);
            printf("\n����������� � ������������� ������:\n");
            for (i = 0; i < read_len; i++) {
                printf("%llu %llu ", c1[i], c2[i]);
                // %d %c %s
            }
            write_encoded_toFile("encrypted_message.txt", c1, c2, read_len);
            break;
        }
        case 2: {
            decrypt_message(read_c1, read_c2, read_len, p, x, decrypted_message);
            printf("\n������������ �����������: %s\n", decrypted_message);
            write_decoded_toFile("decrypted_message.txt", decrypted_message);
            break;
        }
        }

        strcpy(decrypted_message, "");
        read_len = 0;

        fflush(stdin);

        printf("\n");
        system("pause");
        system("cls");
    }
}
