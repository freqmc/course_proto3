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
    int cpu_limit; // ����� ��� �������� ����������
    int ram_limit; // ����� ��� �������� ����������� ������
    int disk_limit; // ����� ��� �������� ��������� ������������
} Thresholds;

Thresholds limits = { 0, 0, 0 };

void SetCheckValues();
int CheckThreatLevel(InputValues values);
void ReadFromLogFile(const wchar_t* filename);
void GenerateLogFile(const wchar_t* filename, int entries);

int main() {
    setlocale(LC_CTYPE, ""); // ������������� ���������� ������
    wchar_t filename[256];
    int choice;
    int num_of_logs; // ������� �������� ���������� �������
    do {
        printf("�������� ����������� �������:\n");
        printf("1) ������� ��������� ��������\n");
        printf("2) ������ ���-�����\n");
        printf("3) ������������� ������ ��� ���-�����\n");
        printf("��� ������ �� ��������� ������� �� 0\n");
        scanf("%d", &choice);
        switch (choice)
        {
        case 1:
            SetCheckValues();
            break;
        case 2:
            printf("������� ��� ���-����� ��� �������: ");
            wscanf(L"%ls", filename);
            ReadFromLogFile(filename);
            break;
        case 3:
            printf("������� ��� ���-����� ��� ����������: ");
            wscanf(L"%ls", filename);
            printf("������� ���������� �����: ");
            scanf("%d", &num_of_logs);
            GenerateLogFile(filename, num_of_logs);
            break;
        case 0:
            break;
        default:
            printf("��� ����� �������.\n");
        }
    } while (choice != 0);
    return 0;
}

void SetCheckValues() {
    printf("������� ��������� �������� ��� �������� ���������� (0-100): ");
    scanf("%d", &limits.cpu_limit);
    printf("������� ��������� �������� ��� �������� ����������� ������ (0-100): ");
    scanf("%d", &limits.ram_limit);
    printf("������� ��������� �������� ��� �������� ��������� ������������ (0-100): ");
    scanf("%d", &limits.disk_limit);
    printf("��������� �������� �����������.\n");
}

int CheckThreatLevel(InputValues values) {
    int below_threshold = 0;

    // ���������, ������� �������� ���� �������� �������
    if (values.cpu_load < limits.cpu_limit) {
        below_threshold++;
    }
    if (values.ram_load < limits.ram_limit) {
        below_threshold++;
    }
    if (values.disk_load < limits.disk_limit) {
        below_threshold++;
    }

    // ���������� ������� ������
    return below_threshold; // ������ ���������� ����_threshold
}

void ReadFromLogFile(const wchar_t* filename) {
    FILE* log_file = _wfopen(filename, L"r, ccs=UTF-8");
    if (!log_file) {
        perror("�� ������� ������� ����");
        exit(EXIT_FAILURE);
    }

    InputValues values;
    wchar_t line[256]; // ����� ��� ������
    wchar_t threats[100][256]; // ������ ����� ��� ����� (�� ����� 100 �������)
    int threats_count = 0; // ������� �����

    // ��������� ������ �� �����
    while (fgetws(line, sizeof(line) / sizeof(wchar_t), log_file)) {
        // �������� ��������
        values.cpu_load = -1;
        values.ram_load = -1;
        values.disk_load = -1;

        // ������������ ������
        wchar_t* cpu_str = wcsstr(line, L"�������� ����������");
        wchar_t* ram_str = wcsstr(line, L"�������� ����������� ������");
        wchar_t* disk_str = wcsstr(line, L"�������� ��������� ������������");

        // ���� ������� ��������, ��������� ��
        if (cpu_str) {
            swscanf(cpu_str, L"�������� ���������� = %d%%", &values.cpu_load);
        }
        if (ram_str) {
            swscanf(ram_str, L"�������� ����������� ������ = %d%%", &values.ram_load);
        }
        if (disk_str) {
            swscanf(disk_str, L"�������� ��������� ������������ = %d%%", &values.disk_load);
        }

        // �������� ������� ������
        int below_threshold = CheckThreatLevel(values);

        // ��������� �������� ������
        if (below_threshold > 0) {
            wchar_t threatLevel[20];
            switch (below_threshold) {
            case 3:
                wcscpy(threatLevel, L"�������");
                break;
            case 2:
                wcscpy(threatLevel, L"�������");
                break;
            case 1:
                wcscpy(threatLevel, L"������");
                break;
            default:
                continue; // ���������� ���������, ����������
            }

            swprintf(threats[threats_count++], 256, L"������� ������: %ls, �������� ����������: %d%%, �������� ����������� ������: %d%%, �������� ��������� ������������: %d%%\n",
                threatLevel, values.cpu_load, values.ram_load, values.disk_load);
        }
    }

    fclose(log_file);

    // ���� ���� ������, ��������� ������������ ������� ������� ��� ����������
    if (threats_count > 0) {
        printf("�������� ������� ����� ��� ����������:\n");
        printf("1) �������\n");
        printf("2) �������\n");
        printf("3) ������\n");
        printf("������� ����� ������ (0 ��� ������): ");
        int chosenLevel;
        scanf("%d", &chosenLevel);

        // ������ �� ���������� � ����
        if (chosenLevel > 0 && chosenLevel <= 3) {
            wchar_t output_filename[256];
            printf("������� ��� ����� ��� ����������: ");
            wscanf(L"%ls", output_filename);
            FILE* output_file = _wfopen(output_filename, L"w, ccs=UTF-8");
            if (!output_file) {
                perror("�� ������� ������� ���� ��� ������");
                exit(EXIT_FAILURE);
            }

            // ������ ����� � ����
            for (int i = 0; i < threats_count; i++) {
                if ((chosenLevel == 1 && wcsstr(threats[i], L"�������")) ||
                    (chosenLevel == 2 && wcsstr(threats[i], L"�������")) ||
                    (chosenLevel == 3 && wcsstr(threats[i], L"������"))) {
                    fputws(threats[i], output_file);
                }
            }

            fclose(output_file);
            wprintf(L"����� ������� �������� � ���� '%ls'.\n", output_filename);
        }
        else {
            wprintf(L"����� ��� ����������.\n");
        }
    }
    else {
        wprintf(L"�� ������� ������� ������ �� �����. ���������, ��� ������ ���������� ��� ������ �����������.\n");
    }
}

void GenerateLogFile(const wchar_t* filename, int entries) {
    FILE* log_file = _wfopen(filename, L"w, ccs=UTF-8");
    if (!log_file) {
        perror("�� ������� ������� ����");
        exit(EXIT_FAILURE);
    }

    // ������������� ���������� ��������� �����
    srand((unsigned int)time(NULL));

    // ������ � ��������� ����������
    const wchar_t* metrics[] = {
        L"�������� ����������",
        L"�������� ����������� ������",
        L"�������� ��������� ������������"
    };

    // ��������� ������� ���-�����
    for (int i = 0; i < entries; i++) {
        // ������ ��� �������� �������� ��������
        int values[3];
        values[0] = rand() % 101; // �������� ����������
        values[1] = rand() % 101; // �������� ����������� ������
        values[2] = rand() % 101; // �������� ��������� ������������

        // ������ �������� ��� �������������
        int indices[3] = { 0, 1, 2 };

        // ������������ ������� (�����-����)
        for (int j = 2; j > 0; j--) {
            int k = rand() % (j + 1);
            int temp = indices[j];
            indices[j] = indices[k];
            indices[k] = temp;
        }

        // ��������� ������ � ���������� � ����
        fwprintf(log_file, L"%ls = %d%%, %ls = %d%%, %ls = %d%%\n",
            metrics[indices[0]], values[indices[0]],
            metrics[indices[1]], values[indices[1]],
            metrics[indices[2]], values[indices[2]]);
    }

    fclose(log_file);
    wprintf(L"���-���� ������� ������ � %d �������� � '%ls'.\n", entries, filename);
}