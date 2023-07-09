temp_bin = "C:\\Users\\titip\\AppData\\Local\\Temp\\main_oxrs71xy.tempbin"

import lief

def get_linked_libraries_and_runpath(binary_path):
    binary = lief.parse(binary_path)

    linked_libraries = []
    runpath = None

    for library in binary.libraries:
        linked_libraries.append(library)

    dynamic_entries = binary.dynamic_entries
    for entry in dynamic_entries:
        if entry.tag == lief.ELF.DYNAMIC_TAGS.RUNPATH:
            runpath = entry.name

    return linked_libraries, runpath

# Exemple d'utilisation
linked_libraries, runpath = get_linked_libraries_and_runpath(temp_bin)

print("Bibliothèques liées :")
for library in linked_libraries:
    print(library)

print("\nChemin d'exécution (runpath) :")
print(runpath)