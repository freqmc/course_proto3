#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <locale.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>

typedef struct {
    int cpu_load;
    int ram_load;
    int disk_load;
} InputValues;

typedef struct {
    int cpu_limit; // Порог для загрузки процессора
    int ram_limit; // Порог для загрузки оперативной памяти
    int disk_limit; // Порог для загрузки дискового пространства
} Thresholds;

Thresholds limits = { 0, 0, 0 };

void SetCheckValues();
int CheckThreatLevel(InputValues values);
void ReadFromLogFile(const wchar_t* filename);
void GenerateLogFile(const wchar_t* filename, int entries);

int main() {
    setlocale(LC_CTYPE, ""); // Автоматически установить локаль
    wchar_t filename[256];
    int choice;
    int num_of_logs; // Укажите желаемое количество записей
    do {
        printf("Выберите необходимую функцию:\n");
        printf("1) Указать пороговые значения\n");
        printf("2) Анализ лог-файла\n");
        printf("3) Сгенерировать данные для лог-файла\n");
        printf("Для выхода из программы нажмите на 0\n");
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            SetCheckValues();
            break;
        case 2:
            printf("Введите имя лог-файла для анализа: ");
            wscanf(L"%ls", filename);
            ReadFromLogFile(filename);
            break;
        case 3:
            printf("Введите имя лог-файла для сохранения: ");
            wscanf(L"%ls", filename);
            printf("Введите количество логов: ");
            scanf("%d", &num_of_logs);
            GenerateLogFile(filename, num_of_logs);
            break;
        case 0:
            break;
        default:
            printf("Нет такой функции.\n");
        }
    } while (choice != 0);
    return 0;
}

void SetCheckValues() {
    printf("Введите пороговое значение для загрузки процессора (0-100): ");
    scanf("%d", &limits.cpu_limit);
    printf("Введите пороговое значение для загрузки оперативной памяти (0-100): ");
    scanf("%d", &limits.ram_limit);
    printf("Введите пороговое значение для загрузки дискового пространства (0-100): ");
    scanf("%d", &limits.disk_limit);
    printf("Пороговые значения установлены.\n");
}

int CheckThreatLevel(InputValues values) {
    int below_threshold = 0;

    // Проверяем, сколько значений ниже заданных порогов
    if (values.cpu_load < limits.cpu_limit) {
        below_threshold++;
    }
    if (values.ram_load < limits.ram_limit) {
        below_threshold++;
    }
    if (values.disk_load < limits.disk_limit) {
        below_threshold++;
    }

    // Определяем уровень угрозы
    return below_threshold; // Вернем количество ниже_threshold
}

void ReadFromLogFile(const wchar_t* filename) {
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("Не удалось открыть файл");
        exit(EXIT_FAILURE);
    }

    InputValues values;
    wchar_t line[256]; // Буфер для строки
    wchar_t threats[100][256]; // Массив строк для угроз (не более 100 записей)
    int threats_count = 0; // Счетчик угроз

    // Считываем строки из файла
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        // Обнуляем значения
        values.cpu_load = -1;
        values.ram_load = -1;
        values.disk_load = -1;

        // Обрабатываем строки
        wchar_t* cpu_str = wcsstr(line, L"Загрузка процессора");
        wchar_t* ram_str = wcsstr(line, L"Загрузка оперативной памяти");
        wchar_t* disk_str = wcsstr(line, L"Загрузка дискового пространства");

        // Если найдены значения, извлекаем их
        if (cpu_str) {
            swscanf(cpu_str, L"Загрузка процессора = %d%%", &values.cpu_load);
        }
        if (ram_str) {
            swscanf(ram_str, L"Загрузка оперативной памяти = %d%%", &values.ram_load);
        }
        if (disk_str) {
            swscanf(disk_str, L"Загрузка дискового пространства = %d%%", &values.disk_load);
        }

        // Получаем уровень угрозы
        int below_threshold = CheckThreatLevel(values);

        // Сохраняем описание угрозы
        if (below_threshold > 0) {
            wchar_t threatLevel[20];
            switch (below_threshold) {
            case 3:
                wcscpy(threatLevel, L"ВЫСОКИЙ");
                break;
            case 2:
                wcscpy(threatLevel, L"СРЕДНИЙ");
                break;
            case 1:
                wcscpy(threatLevel, L"НИЗКИЙ");
                break;
            default:
                continue; // Нормальное состояние, пропускаем
            }

            swprintf(threats[threats_count++], 256, L"Уровень угрозы: %ls, Загрузка процессора: %d%%, Загрузка оперативной памяти: %d%%, Загрузка дискового пространства: %d%%\n",
                threatLevel, values.cpu_load, values.ram_load, values.disk_load);
        }
    }

    fclose(log_file);

    // Если есть угрозы, предложим пользователю выбрать уровень для сохранения
    if (threats_count > 0) {
        printf("Выберите уровень угроз для сохранения:\n");
        printf("1) ВЫСОКИЙ\n");
        printf("2) СРЕДНИЙ\n");
        printf("3) НИЗКИЙ\n");
        printf("Введите номер уровня (0 для выхода): ");
        int chosenLevel;
        scanf("%d", &chosenLevel);

        // Запрос на сохранение в файл
        if (chosenLevel > 0 && chosenLevel <= 3) {
            wchar_t output_filename[256];
            printf("Введите имя файла для сохранения: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("Не удалось открыть файл для записи");
                exit(EXIT_FAILURE);
            }

            // Запись угроз в файл
            for (int i = 0; i < threats_count; i++) {
                if ((chosenLevel == 1 && wcsstr(threats[i], L"ВЫСОКИЙ")) ||
                    (chosenLevel == 2 && wcsstr(threats[i], L"СРЕДНИЙ")) ||
                    (chosenLevel == 3 && wcsstr(threats[i], L"НИЗКИЙ"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"Вывод успешно сохранен в файл '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"Выход без сохранения.\n");
        }
    }
    else {
        wprintf(L"Не удалось считать данные из файла. Убедитесь, что формат правильный или данные отсутствуют.\n");
    }
}

void GenerateLogFile(const wchar_t* filename, int entries) {
    FILE* log_file = _wfopen(filename, L"w, ccs=UTF-8");
    if (!log_file) {
        perror("Не удалось открыть файл");
        exit(EXIT_FAILURE);
    }

    // Инициализация генератора случайных чисел
    srand((unsigned int)time(NULL));

    // Массив с основными значениями
    const wchar_t* metrics[] = {
        L"Загрузка процессора",
        L"Загрузка оперативной памяти",
        L"Загрузка дискового пространства"
    };

    // Генерация записей лог-файла
    for (int i = 0; i < entries; i++) {
        // Массив для хранения значений загрузки
        int values[3];
        values[0] = rand() % 101; // Загрузка процессора
        values[1] = rand() % 101; // Загрузка оперативной памяти
        values[2] = rand() % 101; // Загрузка дискового пространства

        // Массив индексов для перемешивания
        int indices[3] = { 0, 1, 2 };

        // Перемешиваем индексы (фишер-йетс)
        for (int j = 2; j > 0; j--) {
            int k = rand() % (j + 1);
            int temp = indices[j];
            indices[j] = indices[k];
            indices[k] = temp;
        }

        // Формируем строку и записываем в файл
        fwprintf(log_file, L"%ls = %d%%, %ls = %d%%, %ls = %d%%\n",
            metrics[indices[0]], values[indices[0]],
            metrics[indices[1]], values[indices[1]],
            metrics[indices[2]], values[indices[2]]);
    }

    fclose(log_file);
    wprintf(L"Лог-файл успешно создан с %d записями в '%ls'.\n", entries, filename);
}