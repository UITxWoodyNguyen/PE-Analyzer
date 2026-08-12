#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *marker_name = "pe_analyzer_lab_marker.txt";
    const char *marker_text =
        "This file was created by a harmless PE Analyzer lab sample.\r\n";
    char module_path[MAX_PATH] = {0};
    DWORD written = 0;

    GetModuleFileNameA(NULL, module_path, sizeof(module_path));
    printf("PE Analyzer lab sample (benign)\n");
    printf("Executable: %s\n", module_path[0] ? module_path : "<unknown>");
    printf("Process ID: %lu\n", (unsigned long)GetCurrentProcessId());

    HANDLE marker = CreateFileA(marker_name, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (marker == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Could not create %s (error %lu).\n", marker_name,
                (unsigned long)GetLastError());
        return 1;
    }

    BOOL ok = WriteFile(marker, marker_text, (DWORD)strlen(marker_text),
                        &written, NULL);
    CloseHandle(marker);
    if (!ok) {
        fprintf(stderr, "Could not write marker (error %lu).\n",
                (unsigned long)GetLastError());
        return 1;
    }

    printf("Created %s (%lu bytes).\n", marker_name, (unsigned long)written);
    return 0;
}