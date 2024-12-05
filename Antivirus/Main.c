#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>
#include <openssl/sha.h>

// ====================================== Взаимодействие с бд ======================================
sqlite3 *db;
// Функция для открытия базы данных и создания таблицы (signatures)
void initialize_db(sqlite3 **db) {
    const char *create_signatures_table  =
        "CREATE TABLE IF NOT EXISTS Signatures ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "signature BLOB UNIQUE NOT NULL);";

    const char *create_found_files_table =
        "CREATE TABLE IF NOT EXISTS FoundFiles ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "path TEXT UNIQUE NOT NULL, "
        "offset INTEGER NOT NULL, "
        "signature BLOB NOT NULL, "
        "status INTEGER NOT NULL DEFAULT 0);";

    const char *create_quar_table =
        "CREATE TABLE IF NOT EXISTS QuarTable ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "path TEXT UNIQUE NOT NULL, "
        "hash TEXT UNIQUE NOT NULL);";

    char *err_msg = NULL;

    // Открываем базу данных
    if (sqlite3_open("antivir.db", db) != SQLITE_OK) {
        fprintf(stderr, "Ошибка открытия бд: %s\n", sqlite3_errmsg(*db));
        exit(1);
    }

    // Создаём таблицы
    if (sqlite3_exec(*db, create_signatures_table, NULL, NULL, &err_msg) != SQLITE_OK ||
        sqlite3_exec(*db, create_found_files_table, NULL, NULL, &err_msg) != SQLITE_OK || 
        sqlite3_exec(*db, create_quar_table, NULL, NULL, &err_msg) != SQLITE_OK ) {
        fprintf(stderr, "SQL error: %s\n", err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(*db);
        exit(1);
    }

    printf("БД инициализирована.\n");
}

// Функция для добавления сигнатуры в таблицу
void insert_signature(const unsigned char *signature, int sig_length) {
    const char *insert_sql = "INSERT INTO Signatures (signature) VALUES (?);";
    sqlite3_stmt *stmt;

    // Подготавливаем запрос
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Привязываем сигнатуру как BLOB
    sqlite3_bind_blob(stmt, 1, signature, sig_length, SQLITE_STATIC);

    // Выполняем запрос
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Ошибка вставки сигнатуры в таблицу: %s\n", sqlite3_errmsg(db));
    } else {
        printf("Сигнатура добавлена.\n");
    }

    sqlite3_finalize(stmt);
}

// Функция для добавления записи в таблицу FoundFiles
void insert_found_file(const char *path, size_t offset, const unsigned char *signature, int sig_length) {
    const char *insert_sql = 
        "INSERT INTO FoundFiles (path, offset, signature, status) VALUES (?, ?, ?, 0);";
    sqlite3_stmt *stmt;

    // Подготавливаем запрос
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Привязываем параметры
    sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);              // Путь к файлу
    sqlite3_bind_int64(stmt, 2, offset);                              // Смещение
    sqlite3_bind_blob(stmt, 3, signature, sig_length, SQLITE_STATIC); // Сигнатура

    // Выполняем запрос
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Failed to insert found file: %s\n", sqlite3_errmsg(db));
    } else {
        printf("Found file inserted successfully: %s at offset %zu\n", path, offset);
    }

    sqlite3_finalize(stmt);
}

// Функция для получения статистики по статусам
void get_info() {
    const char *query = 
        "SELECT "
        "    (SELECT COUNT(*) FROM FoundFiles WHERE status = 0) AS status_0, "
        "    (SELECT COUNT(*) FROM FoundFiles WHERE status = 1) AS status_1, "
        "    (SELECT COUNT(*) FROM FoundFiles WHERE status = 2) AS status_2, "
        "    (SELECT COUNT(*) FROM FoundFiles WHERE status = 3) AS status_3, "
        "    (SELECT COUNT(*) FROM FoundFiles WHERE status = 4) AS status_4;";

    sqlite3_stmt *stmt;

    // Подготавливаем SQL-запрос
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Выполняем запрос
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int status_0 = sqlite3_column_int(stmt, 0);
        int status_1 = sqlite3_column_int(stmt, 1);
        int status_2 = sqlite3_column_int(stmt, 2);
        int status_3 = sqlite3_column_int(stmt, 3);
        int status_4 = sqlite3_column_int(stmt, 4);

        printf("Статистика по статусам:\n");
        printf("Файлы со статусом 0 'неопределен': %d\n", status_0);
        printf("Файлы со статусом 1 'удалить': %d\n", status_1);
        printf("Файлы со статусом 2 'лечить': %d\n", status_2);
        printf("Файлы со статусом 3 'карантин': %d\n", status_3);
        printf("Файлы со статусом 4 'разрешить': %d\n", status_4);
    } else {
        fprintf(stderr, "Failed to retrieve data: %s\n", sqlite3_errmsg(db));
    }

    // Завершаем обработку запроса
    sqlite3_finalize(stmt);
}

// Функция для вывода строк с заданным статусом
void display_files_with_status(int status) {
    const char *query = "SELECT id, path FROM FoundFiles WHERE status = ?;";
    sqlite3_stmt *stmt;

    // Подготовка SQL-запроса
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Привязываем статус к запросу
    if (sqlite3_bind_int(stmt, 1, status) != SQLITE_OK) {
        fprintf(stderr, "Ошибка привязки параметра: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    printf("Файлы со статусом %d:\n", status);
    printf("ID | Путь\n");
    printf("--------------------------\n");

    // Выполнение запроса и вывод результатов
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *path = (const char *)sqlite3_column_text(stmt, 1);

        printf("%d | %s\n", id, path);
    }

    // Освобождение ресурсов
    sqlite3_finalize(stmt);
}

// Функция для изменения статуса записи по ID
void update_status_by_id(int id, int new_status) {
    const char *query = "UPDATE FoundFiles SET status = ? WHERE id = ?;";
    sqlite3_stmt *stmt;

    // Подготовка SQL-запроса
    if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Привязываем новый статус к запросу
    if (sqlite3_bind_int(stmt, 1, new_status) != SQLITE_OK) {
        fprintf(stderr, "Ошибка привязки нового статуса: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    // Привязываем ID записи к запросу
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        fprintf(stderr, "Ошибка привязки ID: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return;
    }

    // Выполнение запроса
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        fprintf(stderr, "Ошибка выполнения запроса: %s\n", sqlite3_errmsg(db));
    } else {
        printf("Статус записи с ID %d успешно изменен на %d.\n", id, new_status);
    }

    // Освобождение ресурсов
    sqlite3_finalize(stmt);
}

// ====================================== Обработка таблицы FoundFiles ======================================
// Удаление записи по id
void del_by_id(int id) {
    const char *sql_delete = "DELETE FROM FoundFiles WHERE id = ?"; // SQL запрос для удаления записи по id

    // Подготовка запроса для удаления записи из базы данных
    sqlite3_stmt *delete_stmt;
    if (sqlite3_prepare_v2(db, sql_delete, -1, &delete_stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса на удаление записи: %s\n", sqlite3_errmsg(db));
    }

    // Привязываем id к запросу на удаление
    sqlite3_bind_int(delete_stmt, 1, id);
    
    // Выполняем запрос на удаление записи
    if (sqlite3_step(delete_stmt) != SQLITE_DONE) {
        fprintf(stderr, "Ошибка удаления записи с id %d: %s\n", id, sqlite3_errmsg(db));
    } else {
        printf("Запись с id %d удалена из базы данных.\n", id);
    }
    
    // Освобождаем ресурсы для запроса на удаление
    sqlite3_finalize(delete_stmt);

    return;
}

// ----- удаление -----
// Удаление файла
void del_files_with_status_1() {
    printf("===== Удаление =====\n");

    sqlite3_stmt *stmt;
    const char *sql_select = "SELECT id, path FROM FoundFiles WHERE status = 1"; // SQL запрос для выборки файлов со статусом 1
    
    // Подготовка SQL запроса для выборки
    if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки SQL запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    // Выполнение выборки и удаление файлов
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        // Получаем id и путь из результата выборки
        int id = sqlite3_column_int(stmt, 0);
        const char *path = (const char *)sqlite3_column_text(stmt, 1);
        
        // Удаляем файл с диска
        if (unlink(path) == 0) {
            printf("Файл %s удален успешно.\n", path);
            del_by_id(id);  

        } else {
            fprintf(stderr, "Ошибка удаления файла %s: %s\n", path, strerror(errno));
        }
    }

    // Освобождаем ресурсы для запроса на выборку
    sqlite3_finalize(stmt);
}

// ----- Лечение -----
// Функция для удаления сигнатуры из файла
int remove_signature(const char *file_path, long offset, size_t sig_len) {
    FILE *file = fopen(file_path, "rb+");
    if (!file) {
        perror("Ошибка открытия файла");
        return -1;
    }

    // Переходим к смещению
    if (fseek(file, offset + sig_len, SEEK_SET) != 0) {
        perror("Ошибка перехода к смещению");
        fclose(file);
        return -1;
    }

    // Получаем размер файла
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < 0) {
        perror("Ошибка получения размера файла");
        fclose(file);
        return -1;
    }

    // Читаем данные после сигнатуры
    size_t remaining_size = file_size - (offset + sig_len);
    char *buffer = (char *)malloc(remaining_size);
    if (!buffer) {
        perror("Ошибка выделения памяти");
        fclose(file);
        return -1;
    }
    fseek(file, offset + sig_len, SEEK_SET);
    fread(buffer, 1, remaining_size, file);

    // Перезаписываем файл, пропуская сигнатуру
    fseek(file, offset, SEEK_SET);
    fwrite(buffer, 1, remaining_size, file);

    // Укорачиваем файл
    if (ftruncate(fileno(file), file_size - sig_len) != 0) {
        perror("Ошибка укорачивания файла");
        free(buffer);
        fclose(file);
        return -1;
    }

    free(buffer);
    fclose(file);
    return 0;
}

// Лечение файлов
void heal_files_with_status_2() {
    printf("===== Лечение =====\n");

    sqlite3_stmt *stmt;
    const char *sql_select = "SELECT id, path, offset, LENGTH(signature) FROM FoundFiles WHERE status = 2";

    if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *path = (const char *)sqlite3_column_text(stmt, 1);
        long offset = sqlite3_column_int64(stmt, 2);
        size_t sig_len = sqlite3_column_int(stmt, 3);

        printf("Обрабатывается файл: %s, ID: %d, смещение: %ld, длина сигнатуры: %zu\n", path, id, offset, sig_len);

        if (remove_signature(path, offset, sig_len) == 0) {
            // Успешно удалили сигнатуру, обновляем статус
            del_by_id(id);

        } else {
            fprintf(stderr, "Ошибка обработки файла: %s\n", path);
        }
    }

    sqlite3_finalize(stmt);
}

// ----- карантин -----
// Вычисление SHA256-хэша от пути
void calculate_hash(const char *path, char *hash_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)path, strlen(path), hash);

    // Преобразование хэша в строку
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_out + (i * 2), "%02x", hash[i]);
    }
    hash_out[SHA256_DIGEST_LENGTH * 2] = '\0'; // Завершающий символ
}

// Шифрование файла с использованием XOR
int xor_encrypt_file(const char *file_path, unsigned char xor_key) {
    FILE *file = fopen(file_path, "rb+");
    if (!file) {
        perror("Ошибка при открытии файла для шифрования");
        return -1;
    }

    // Чтение и шифрование содержимого файла
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        perror("Ошибка выделения памяти");
        fclose(file);
        return -1;
    }

    fread(buffer, 1, file_size, file);
    rewind(file);

    for (long i = 0; i < file_size; i++) {
        buffer[i] ^= xor_key;
    }

    fwrite(buffer, 1, file_size, file);
    free(buffer);
    fclose(file);
    return 0;
}

// Основная функция обработки
void quar_files_with_status_3() {
    printf("===== Карантин =====\n");


    sqlite3_stmt *stmt;
    const char *select_query = "SELECT id, path FROM FoundFiles WHERE status = 3;";
    const char *insert_query = "INSERT INTO QuarTable (id, path, hash) VALUES (?, ?, ?);";

    // Создание директории Quarantine, если она не существует
    if (mkdir("Quarantine", 0777) && errno != EEXIST) {
        perror("Ошибка создания директории Quarantine");
        return;
    }

    // Подготовка запроса для выборки файлов со статусом 3
    if (sqlite3_prepare_v2(db, select_query, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        return;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *path = (const char *)sqlite3_column_text(stmt, 1);

        // Вычисление хэша
        char hash[SHA256_DIGEST_LENGTH * 2 + 1];
        calculate_hash(path, hash);

        // Шифрование файла
        if (xor_encrypt_file(path, 0x39) != 0) {
            fprintf(stderr, "Ошибка шифрования файла: %s\n", path);
            continue;
        }

        // Перемещение файла в папку Quarantine с новым именем
        char new_path[512];
        snprintf(new_path, sizeof(new_path), "Quarantine/%s", hash);
        if (rename(path, new_path) != 0) {
            perror("Ошибка перемещения файла");
            continue;
        }

        // Добавление записи в таблицу quar_table
        sqlite3_stmt *insert_stmt;
        if (sqlite3_prepare_v2(db, insert_query, -1, &insert_stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "Ошибка подготовки запроса вставки: %s\n", sqlite3_errmsg(db));
            continue;
        }

        sqlite3_bind_text(insert_stmt, 2, path, -1, SQLITE_STATIC);
        sqlite3_bind_text(insert_stmt, 3, hash, -1, SQLITE_STATIC);

        if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
            fprintf(stderr, "Ошибка выполнения запроса вставки: %s\n", sqlite3_errmsg(db));
        }

        sqlite3_finalize(insert_stmt);

        del_by_id(id);
    }

    sqlite3_finalize(stmt);
}

// Обработка установленной информации в таблице FoundFiles
void process_table_info() {
    del_files_with_status_1();
    heal_files_with_status_2();
    quar_files_with_status_3();

    return;
}

// ====================================== Поиск сигнатур в файлe ======================================
// Функция для поиска сигнатур из БД в файле
void search_signatures_in_file(const char *filename) {
    const char *sig_query_sql = "SELECT signature FROM Signatures;";
    sqlite3_stmt *stmt;
    FILE *file;
    size_t file_size;

// ---------- Читаем файл в память ----------
    // Открываем файл для чтения
    file = fopen(filename, "rb");
    if (!file) {
        perror("Ошибка открытия файла");
        return;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        perror("Ошибка выделения памяти");
        fclose(file);
        return;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);
// ------------------------------------------

    // Подготавливаем запрос для получения сигнатур из БД
    if (sqlite3_prepare_v2(db, sig_query_sql, -1, &stmt, 0) != SQLITE_OK) {
        fprintf(stderr, "Ошибка подготовки запроса: %s\n", sqlite3_errmsg(db));
        free(buffer);
        return;
    }


    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *signature = sqlite3_column_blob(stmt, 0);
        int sig_size = sqlite3_column_bytes(stmt, 0);

        // Поиск сигнатуры в файле
        for (int i = 0; i <= (int)file_size - (int)sig_size; i++) {
            if (memcmp(buffer + i, signature, sig_size) == 0) {
                printf("Сигнатура найдена в файле %s по смещению %zu\n", filename, i);

                // Добавляем запись о найденной сигнатуре в таблицу FoundFiles
                insert_found_file(filename, i, signature, sig_size);

                found = 1;
                break;
            }
        }
        if (found) break;
    }

    free(buffer);
    sqlite3_finalize(stmt);
    return;
}
// ====================================== Поиск файлов в директории ======================================
void listFilesRecursive(const char *basePath) {
    struct dirent *dp;
    DIR *dir = opendir(basePath);

    // Проверяем, удалось ли открыть каталог
    if (dir == NULL) {
        perror("opendir");
        return;
    }

    while ((dp = readdir(dir)) != NULL) {
        char path[1024];
        struct stat statbuf;

        // Пропускаем текущий и родительский каталоги
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        // Формируем полный путь к элементу
        snprintf(path, sizeof(path), "%s/%s", basePath, dp->d_name);

        // Получаем информацию об элементе
        if (stat(path, &statbuf) == -1) {
            perror("stat");
            continue;
        }

        // Если это файл, выводим его
        if (S_ISREG(statbuf.st_mode)) {
            // printf("File: %s\n", path);
            search_signatures_in_file(path);
        }

        // Если это директория, рекурсивно обрабатываем её
        if (S_ISDIR(statbuf.st_mode)) {
            // printf("Directory: %s\n", path);
            listFilesRecursive(path);
        }
    }

    // Закрываем каталог
    closedir(dir);
}


void main(int argc, char *argv[]) {
    initialize_db(&db);
    char command[100];
    const char *startPath = "../ForAntivirus"; // Директория по умолчанию
    int number = 0;  // Переменная для хранения числа

    while (1) {
        printf("> ");
        if (fgets(command, 100, stdin) == NULL) {
            perror("Ошибка ввода");
            continue;
        }

        // Удаляем символ новой строки в конце команды
        command[strcspn(command, "\n")] = '\0';

        if (strcmp(command, "check") == 0) {
            listFilesRecursive(startPath);          // запускаем поиск вирусов

        } else if (strcmp(command, "start") == 0) {
            process_table_info();                                  // запускаем выполнение установленных работ

        } else if (strcmp(command, "exit") == 0) {
            break;                                  // выход из программы

        } else if (strcmp(command, "info") == 0) {
            get_info();

        } else if (strcmp(command, "info0") == 0) {
            display_files_with_status(0);

        } else if (sscanf(command, "info %d", &number) == 1) {
            display_files_with_status(number);

        } else if (sscanf(command, "del %d", &number) == 1) {
            update_status_by_id(number, 1);

        } else if (sscanf(command, "heal %d", &number) == 1) {
            update_status_by_id(number, 2);

        } else if (sscanf(command, "quar %d", &number) == 1) {
            update_status_by_id(number, 3);

        } else if (sscanf(command, "allow %d", &number) == 1) {
            update_status_by_id(number, 4);

        } else {
            printf("Неизвестная команда. Попробуйте снова.\n");
        }
    }

    // Закрываем базу данных
    sqlite3_close(db);
    return;
}




// добавление сигнатуры в бд
//    unsigned char signature[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
//    insert_signature(signature, 0x10);