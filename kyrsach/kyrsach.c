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
        perror("Помилка відкриття файлу для запису");
        return;
    }

    // Записуємо зашифроване повідомлення
    for (i = 0; i < len; i++) {
        fprintf(file, "%llu %llu ", c1[i], c2[i]);
    }

    fclose(file);
}


void write_decoded_toFile(const char* filename, char* message) {
    int i;
    FILE* file = fopen(filename, "w");
    if (!file) {
        perror("Помилка відкриття файлу для запису");
        return;
    }

    // Записуємо зашифроване повідомлення
    fprintf(file, "%s", message);

    fclose(file);

}


void read_encoded_fromFile(const char* filename, unsigned long long* c1, unsigned long long* c2, int* len) {
    int i;

    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Помилка відкриття файлу для зчитування");
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
        perror("Помилка відкриття файлу для запису");
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
    printf("\nВведіть своє зашифроване повідомлення:\n");

    while (*len < 128) {
        fgets(buffer, sizeof(buffer), stdin);

        if (buffer[0] == '\n') {
            break;
        }

        if (sscanf(buffer, "%llu %llu", &c1[*len], &c2[*len]) == 2) {
            (*len)++;
        }
        else {
            printf("Помилка! Введіть два числа, розділені пробілом.\n");
        }
    }
}


void read_decoded_fromConsole(char* message, int* len) {
    printf("\nВведіть своє повідомлення для шифрування: ");
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

    printf("Параметри за замовчуванням:\n");
    printf("-- p (просте число): %llu\n", *p);
    printf("-- g (генератор): %llu\n", *g);
    printf("-- x (секретний ключ): %llu\n", *x);
    printf("-- y (публічний ключ): %llu\n", *y);
    printf("\nЯкі параметри використовувати:\n");
    printf("0:  Використовувати власні параметри\n");
    printf("1:  Параметри за замовчуванням \n");
    //while (getchar() != '\n');


    do {
        scanf("%d", &user_keyInput_option);
        if (user_keyInput_option < 0 || user_keyInput_option > 1) {
            printf("Неправильний ввід. Має бути 0 або 1\n");
        }
    } while (user_keyInput_option < 0 || user_keyInput_option > 1);

    // Встановлення параметрів шифрування
    if (user_keyInput_option == 0) {
        printf("Введіть просте число p (бажано більше): ");
        do {
            scanf_s("%llu", p);
            isPrime = is_prime(*p);
            if (!isPrime) {
                printf("Це не просте число (107, 109, 113, 229, 337, 401...)!\n");
            }
        } while (!isPrime);

        printf("Введіть число генератор g (1 < g < p - 1): ");
        do {
            scanf_s("%llu", g);
            isGenerator = is_generator(*g, *p);
            if (!isGenerator || *g > *p - 1) {
                printf("Число не підходить!\n");
            }
        } while (!isGenerator || *g > *p - 1);

        printf("Введіть приватний ключ x (1 < x < p - 2): ");
        do {
            scanf_s("%llu", x);
            if (*x <= 1 || *x >= *p - 2) {
                printf("Число не підходить!\n");
            }
        } while (*x <= 1 || *x >= *p - 2);
    }

    // Публічний ключ
    *y = mod_exp(*g, *x, *p);
}


void userDecryptionParameters(unsigned long long* p, unsigned long long* g, unsigned long long* x) {
    int user_keyInput_option = -1;

    bool isPrime,
        isGenerator;

    printf("Параметри за замовчуванням:\n");
    printf("-- p (просте число): %llu\n", *p);
    printf("-- g (генератор): %llu\n", *g);
    printf("-- x (секретний ключ): %llu\n", *x);
    printf("\nЯкі параметри використовувати:\n");
    printf("0:  Використовувати власні параметри\n");
    printf("1:  Параметри за замовчуванням \n");
    //while (getchar() != '\n');

    do {
        scanf("%d", &user_keyInput_option);
        if (user_keyInput_option < 0 || user_keyInput_option > 1) {
            printf("Неправильний ввід. Має бути 0 або 1\n");
        }
    } while (user_keyInput_option < 0 || user_keyInput_option > 1);

    // Встановлення параметрів шифрування
    if (user_keyInput_option == 0) {
        printf("Введіть просте число p (бажано більше): ");
        do {
            scanf_s("%llu", p);
            isPrime = is_prime(*p);
            if (!isPrime) {
                printf("Це не просте число (107, 109, 113, 229, 337, 401...)!\n");
            }
        } while (!isPrime);

        printf("Введіть число генератор g (1 < g < p - 1): ");
        do {
            scanf_s("%llu", g);
            isGenerator = is_generator(*g, *p);
            if (!isGenerator || *g > *p - 1) {
                printf("Число не підходить!\n");
            }
        } while (!isGenerator || *g > *p - 1);

        printf("Введіть приватний ключ x (1 < x < p - 2): ");
        do {
            scanf_s("%llu", x);
            if (*x <= 1 || *x >= *p - 2) {
                printf("Число не підходить!\n");
            }
        } while (*x <= 1 || *x >= *p - 2);
    }
}


int main() {

    system("chcp 1251 & cls");

    unsigned long long
        p,              // Просте число
        g,              // Генератор групи
        x,              // Секретний ключ
        y;              // Публічний ключ
    int read_len = 0,   // Довжина повідомлення шифрування
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

        printf("----------- Шифрування Ель-Гамаля -----------\n");
        printf("Доступні команди:\n");
        printf("0\t Вийти\n");
        printf("1\t Зашифрувати\n");
        printf("2\t Розшифрувати\n");
        printf("Чим бажаєте зайнятись?\n");

        do {
            scanf("%d", &user_action_option);
            if (user_action_option != 0 && user_action_option != 1 && user_action_option != 2) {
                printf("Невідома команда\n");
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
        printf("Звідки брати текст для шифровки?\n");
        printf("0: Вийти\n");
        printf("1: Консоль\n");
        printf("2: Файл\n");

        do {
            scanf("%d", &user_dataSource_option);
            if (user_dataSource_option != 0 && user_dataSource_option != 1 && user_dataSource_option != 2) {
                printf("Невідоме джерело\n");
            }
        } while (user_dataSource_option != 0 && user_dataSource_option != 1 && user_dataSource_option != 2);
        while (getchar() != '\n');

        switch (user_dataSource_option) {
        case 0: { return 0; }
        case 1: {
            if (user_action_option == 1) {
                read_decoded_fromConsole(decrypted_message, &read_len);
                printf("\nВведене повідомлення: %s", decrypted_message);
            }
            else {
                read_encoded_fromConsole(read_c1, read_c2, &read_len);
                printf("\nВведене повідомлення: ");
                for (i = 0; i < read_len; i++) {
                    printf("%llu %llu ", read_c1[i], read_c2[i]);
                }
            }
            break; 
        }
        case 2: {
            if (user_action_option == 1) {
                read_decoded_fromFile("decrypted_message.txt", decrypted_message, &read_len);
                printf("\nПовідомлення:\n%s\n", decrypted_message);
            }
            else {
                read_encoded_fromFile("encrypted_message.txt", read_c1, read_c2, &read_len);
                printf("\nЗашифроване повідомлення:\n");
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
            printf("\nПовідомлення у зашифрованому вигляді:\n");
            for (i = 0; i < read_len; i++) {
                printf("%llu %llu ", c1[i], c2[i]);
                // %d %c %s
            }
            write_encoded_toFile("encrypted_message.txt", c1, c2, read_len);
            break;
        }
        case 2: {
            decrypt_message(read_c1, read_c2, read_len, p, x, decrypted_message);
            printf("\nРозшифроване повідомлення: %s\n", decrypted_message);
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
