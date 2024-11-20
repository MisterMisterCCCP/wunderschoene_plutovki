// Mem_Scan.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <string>
#include <cstdlib> // Für std::stoi
#include <Windows.h>
#include <TlHelp32.h>
#include <cwchar>
#include <vector>
#include <utility>
#include <sstream>

// Funktion zur Umwandlung von std::string in wchar_t*
wchar_t* stringToWideChar(const std::string& str) {
    size_t length = str.length() + 1; // Platz für das nullterminierte Zeichen
    wchar_t* wideStr = new wchar_t[length]; // Speicher reservieren
    size_t convertedChars = 0;

    // Konvertierung von multibyte zu wide character
    mbstowcs_s(&convertedChars, wideStr, length, str.c_str(), length - 1);

    return wideStr; // Zeiger auf das konvertierte wchar_t* zurückgeben
}

std::vector<std::pair<void*, int>> filter_founded_process_memory(
    int valueToFindNext,
    DWORD processID,
    const std::vector<std::pair<void*, int>> &valuesFromPreviousScan
) {
    std::vector<std::pair<void*, int>> foundValues; // Ergebnisliste
    wprintf(L"Searching for nextValue: %d in process ID: %lu\n", valueToFindNext, processID);

    // Prozess öffnen
    HANDLE handleToTheProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (handleToTheProcess == nullptr) {
        wprintf(L"Failed to open process. Error: %lu\n", GetLastError());
        return foundValues;
    }

    // Über die Ergebnisse aus dem vorherigen Scan iterieren
    for (const auto& previousResult : valuesFromPreviousScan) {
        void* address = previousResult.first; // Speicheradresse aus dem vorherigen Scan
        int previousValue = previousResult.second;

        // Speicherinformationen abrufen
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(handleToTheProcess, address, &mbi, sizeof(mbi))) {
            // Überprüfen, ob der Speicherbereich lesbar ist
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_WRITECOPY)) {

                // Speicherbereich auslesen
                int currentValue;
                SIZE_T bytesRead;
                if (ReadProcessMemory(handleToTheProcess, address, &currentValue, sizeof(currentValue), &bytesRead)) {
                    // Prüfen, ob der aktuelle Wert mit dem gesuchten Wert übereinstimmt
                    if (currentValue == valueToFindNext) {
                        foundValues.emplace_back(address, currentValue);
                        wprintf(L"Found matching value: %d at address: 0x%p\n", currentValue, address);
                    }
                }
                else {
                    wprintf(L"Failed to read memory at address: 0x%p. Error: %lu\n", address, GetLastError());
                }
            }
            else {
                wprintf(L"Memory at address: 0x%p is not readable. Skipping.\n", address);
            }
        }
        else {
            wprintf(L"Failed to query memory at address: 0x%p. Error: %lu\n", address, GetLastError());
        }
    }

    // Handle des Prozesses schließen
    CloseHandle(handleToTheProcess);

    return foundValues;
}


std::vector<std::pair<void*, int>> read_and_find_from_process_memory(int valueToFind, DWORD processID) {
    std::vector<std::pair<void*, int>> foundValues; // Ergebnisliste
    wprintf(L"Searching for value: %d in process ID: %lu\n", valueToFind, processID);

    // Prozess öffnen
    HANDLE handleToTheProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (handleToTheProcess == nullptr) {
        wprintf(L"Failed to open process. Error: %lu\n", GetLastError());
        return foundValues;
    }

    // Speicherbereiche durchsuchen
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* address = nullptr; // Startadresse

    while (VirtualQueryEx(handleToTheProcess, address, &mbi, sizeof(mbi))) {
        // Überprüfen, ob der Speicherbereich lesbar ist
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_WRITECOPY)) {

            std::vector<unsigned char> buffer(mbi.RegionSize); // Speicher für den Block
            SIZE_T bytesRead;

            // Speicher auslesen
            if (ReadProcessMemory(handleToTheProcess, address, buffer.data(), mbi.RegionSize, &bytesRead)) {
                // Im Block nach dem Wert suchen
                for (size_t i = 0; i < bytesRead - sizeof(valueToFind); ++i) {
                    int* potentialMatch = reinterpret_cast<int*>(&buffer[i]);
                    if (*potentialMatch == valueToFind) {
                        // Adresse und Wert speichern
                        foundValues.emplace_back(address + i, *potentialMatch);
                    }
                }
            }
        }
        // Zur nächsten Region gehen
        address += mbi.RegionSize;
    }

    // Handle schließen
    CloseHandle(handleToTheProcess);
    wprintf(L"Search completed. Found %zu occurrences.\n", foundValues.size());

    return foundValues;
}

void write_and_save(void* addressToWrite, int valueToWrite, DWORD processID) {
    wprintf(L"Trying to write value: %d at address: 0x%p in process ID: %lu\n", valueToWrite, addressToWrite, processID);

    // Öffne den Prozess mit Schreibrechten und Informationsrechten
    HANDLE handleToTheProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (handleToTheProcess == nullptr) {
        wprintf(L"Failed to open process. Error: %lu\n", GetLastError());
        return;
    }

    // Prüfe die Speicherregion, in der sich die Zieladresse befindet
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(handleToTheProcess, addressToWrite, &mbi, sizeof(mbi)) == 0) {
        wprintf(L"Failed to query memory information for address: 0x%p. Error: %lu\n", addressToWrite, GetLastError());
        CloseHandle(handleToTheProcess);
        return;
    }

    // Überprüfen, ob die Adresse in einem gültigen und beschreibbaren Bereich liegt
    if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE))) {
        wprintf(L"Target address 0x%p is not in a writable memory region.\n", addressToWrite);
        CloseHandle(handleToTheProcess);
        return;
    }

    // Schreibe den Wert in den Speicher des Zielprozesses
    SIZE_T bytesWritten = 0;
    if (WriteProcessMemory(handleToTheProcess, addressToWrite, &valueToWrite, sizeof(valueToWrite), &bytesWritten)) {
        wprintf(L"Successfully wrote value: %d to address: 0x%p. Bytes written: %zu\n", valueToWrite, addressToWrite, bytesWritten);
    }
    else {
        wprintf(L"Failed to write to memory at address: 0x%p. Error: %lu\n", addressToWrite, GetLastError());
    }

    // Handle schließen
    CloseHandle(handleToTheProcess);
}

DWORD find_process_id(const wchar_t* targetExe) {
    DWORD targetID = 0;
    PROCESSENTRY32W entry;  // Unicode-Version
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to take snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    if (Process32FirstW(snapshot, &entry)) {
        do {
            // Verwende einen Case-Insensitive-Vergleich
            if (_wcsicmp(entry.szExeFile, targetExe) == 0) {
                targetID = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    else {
        wprintf(L"Failed to retrieve the first process. Error: %lu\n", GetLastError());
    }

    CloseHandle(snapshot);
    return targetID;
}

int main() {
    std::string input;
    std::vector<std::pair<void*, int>> results;
    while (true) {
        std::cout << "Hello from Mem Scan... enter a command or type ? to find out all commands\n";
        std::getline(std::cin, input);
        if (input == "exit") {
            std::cout << "Exiting program\n";
            break;
        }
        if (input == "?") {
            std::cout << "<target_process> <read_and_find> <value_to_find>\n";
            std::cout << "<target_process> <read_and_find> <value_to_find> <next_value_to_find_optional>\n";
            std::cout << "<target_process> <write_and_save> <value_to_write> <adress_of_the_value_which_becomes_overitten>\n";
            continue;
        }
        // Split input into arguments
        std::vector<std::string> args;
        std::string arg;
        std::istringstream iss(input);
        while (iss >> arg) {
            args.push_back(arg);
        }
        if (args.size() < 2 || (args[1] == "write_and_save" && args.size() != 4) || ((args[1] == "read_and_find" && args.size() != 4) && (args[1] == "read_and_find" && args.size() != 3))) {
            std::cerr << "Invalid command. Usage: Type in ? to see valid commands\n";
            continue;
        }
        std::string target = args[0];
        std::string func = args[1];
        int value;

        wchar_t* wTarget = stringToWideChar(target);
        DWORD targetPID = find_process_id(wTarget);

        if (targetPID == 0) {
            std::cerr << "Error: Could not find process " << target << ".\n";
            delete[] wTarget;
            continue;
        }

        try {
            value = std::stoi(args[2]);
        }
        catch (const std::exception& e) {
            std::cerr << "Error: <value_for_func> must be an integer.\n";
            delete[] wTarget;
            continue;
        }

        if (func == "read_and_find") {
            if (args[3].empty()){
                results = read_and_find_from_process_memory(value, targetPID);
                for (const std::pair<void*, int>& result : results) {
                    void* address = result.first;
                    int foundValue = result.second;
                    wprintf(L"Found value: %d at address: 0x%p\n", foundValue, address);
                }
            }
            else {
                int nextValue;
                try {
                    nextValue = std::stoi(args[3]);
                }
                catch (const std::exception& e) {
                    std::cerr << "Error: <next_value_to_find_optional> must be an integer.\n";
                    delete[] wTarget;
                    continue;
                }
                results = filter_founded_process_memory(nextValue, targetPID, results);
            }
        }
        else if (func == "write_and_save") {
            void* targetAddress;
            try {
                targetAddress = reinterpret_cast<void*>(std::stoull(args[3], nullptr, 16));
            }
            catch (const std::exception& e) {
                std::cerr << "Error: <address_to_write> must be castable to void*.\n";
                delete[] wTarget;
                continue;
            }
            write_and_save(targetAddress, value, targetPID);
        }
        else {
            std::cerr << "Error: Unknown function '" << func << "'.\n";
        }

        delete[] wTarget;
    }
    return 0;
}

/**
// Überprüfen, ob genug Argumente übergeben wurden
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <target.exe> <func> <value_for_func> <adress_to_write>\n";
        return 1;
    }
    std::string target = argv[1];// Erstes Argument: target.exe
    std::cout << "Target application is: " << target << "\n"; // Ausgabe des Targets
    wchar_t* wTarget = stringToWideChar(target);
    DWORD targetPID = find_process_id(wTarget);
    wprintf(L"Das ist die targetPID: %lu von Prozess %ls\n", targetPID, wTarget);
    std::string func = argv[2];  // Zweites Argument: Name der Funktion
    int value;

    try {
        value = std::stoi(argv[3]); // Drittes Argument: Wert (umwandeln in int)
    }
    catch (const std::exception& e) {
        std::cerr << "Error: <value_for_func> must be an integer.\n";
        return 1;
    }

    // Funktionen filtern
    if (func == "read_and_find") {
        // Typ von results explizit angeben
        std::vector<std::pair<void*, int>> results = read_and_find_from_process_memory(value, targetPID);

        // Ergebnisse anzeigen, Typ explizit angegeben
        for (const std::pair<void*, int>& result : results) {
            void* address = result.first;
            int value = result.second;
            wprintf(L"Found value: %d at address: 0x%p\n", value, address);
        }
    }
    else if (func == "write_and_save") {
        void* targetAdress;
        try {
            // Konvertiere den String in eine Ganzzahl (Basis 16 für Hexadezimal)
            targetAdress = reinterpret_cast<void*>(std::stoull(argv[4], nullptr, 16));
        }
        catch(const std::exception & e) {
            std::cerr << "Error: <address_for_func> must be castable to void*.\n";
            return 1;
        }
        write_and_save(targetAdress,value,targetPID);
    }
    else {
        std::cerr << "Error: Unknown function '" << func << "'.\n";
        return 1;
    }
    Found matching value: 27 at address: 0x0000021E3911EA98
Found matching value: 27 at address: 0x0000021E3D881930

    delete[] wTarget;
    return 0;







*/




