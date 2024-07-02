#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>

#define MAX_PATH 256
#define MAX_ANCESTORS 1024

// Structure to hold process information
typedef struct Process
{
    pid_t pid;        // Process ID
    pid_t ppid;       // Parent Process ID
    char name[256];   // Process name
    char status[256]; // Process status
} Process;

// Function to read a specific field from the /proc/[pid]/status file and stores the result in result
bool read_status_field(pid_t pid, const char *field, char *result)
{
    char path[MAX_PATH], buffer[256];
    FILE *status_file;
    snprintf(path, sizeof(path), "/proc/%d/status", pid); // Form the path to the status file

    if ((status_file = fopen(path, "r")) == NULL)
        return false;

    // Read the status file line by line
    while (fgets(buffer, sizeof(buffer), status_file))
    {
        // Check if the line starts with the desired field
        if (strncmp(buffer, field, strlen(field)) == 0)
        {
            sscanf(buffer, "%*s %s", result); // Extract the field's value; ignore the first part and then store the second part in result
            fclose(status_file);
            return true;
        }
    }
    fclose(status_file);
    return false;
}

// Function to get the parent process ID (PPID) of a process
pid_t get_ppid(pid_t pid)
{
    char ppid_str[256];
    return read_status_field(pid, "PPid:", ppid_str) ? atol(ppid_str) : -1; // read the /proc and return the ppid if successful
}

// Function to retrieve and store process details
void get_process_details(pid_t pid, Process *process)
{
    process->pid = pid;
    process->ppid = get_ppid(pid);
    if (!read_status_field(pid, "Name:", process->name)) // Stores name if found else store unknown
    {
        strcpy(process->name, "unknown");
    }
    if (!read_status_field(pid, "State:", process->status)) // Stores status if found else store unknown
    {
        strcpy(process->status, "unknown");
    }
}

// Function to get all descendant processes
void get_all_descendants(pid_t pid, pid_t *descendants, int *count)
{
    // Open the /proc directory, which contains information about all processes
    DIR *dp;

    if ((dp = opendir("/proc")) == NULL)
        return;

    struct dirent *entry;

    // Loop over all directory entries in /proc
    while ((entry = readdir(dp)) != NULL)
    {
        // Check if the current directory entry is a directory (DT_DIR) and its name can be converted to a positive integer
        if (entry->d_type == DT_DIR && atol(entry->d_name) > 0)
        {
            // Convert the directory name to a process ID
            pid_t child_pid = atol(entry->d_name);

            // Check if the parent process ID (PPID) of the child process matches the original pid argument
            if (get_ppid(child_pid) == pid)
            {
                // If the PPID matches, add the child process ID to the descendants array
                descendants[(*count)++] = child_pid;

                // Recursively call get_all_descendants to find all descendant processes of the child process
                get_all_descendants(child_pid, descendants, count);
            }
        }
    }

    // Close the /proc directory stream
    closedir(dp);
}

// Function to print a list of processes
void print_process_list(const char *title, pid_t *pids, int count)
{
    // If no processes were printed, print a message indicating that no direct descendants were found
    if (count == 0)
    {
        printf("No direct descendants found.\n");
        return;
    }

    // Print the title of the process list
    printf("%s\n", title);

    for (int i = 0; i < count; i++)
    {
        char name[256];
        char status[256];
        if (!read_status_field(pids[i], "Name:", name))
        {
            strcpy(name, "unknown");
        }
        if (!read_status_field(pids[i], "State:", status))
        {
            strcpy(status, "unknown");
        }
        printf("%s (%d) [%s]\n", name, pids[i], status);
    }
}

// Function to check if pid2 is descendant of pid1
bool is_descendant(pid_t pid1, pid_t pid2)
{
    while (pid2 > 1)
    {
        if (get_ppid(pid2) == pid1)
            return true;
        pid2 = get_ppid(pid2);
    }
    return false;
}

// Function to check if a process is defunct (zombie)
bool is_defunct(pid_t pid)
{
    char status[256];
    read_status_field(pid, "State:", status); // reads the status
    return strcmp(status, "Z") == 0;          // if Z then return true else false
}

// Function to send a signal to all descendant processes
void signal_all_descendants(pid_t pid, int signal, const char *action)
{
    pid_t descendants[MAX_ANCESTORS];
    int count = 0;

    get_all_descendants(pid, descendants, &count); // get all descendents

    if (count == 0)
    {
        printf("No descendants found to send signal to.\n");
        return;
    }

    for (int i = 0; i < count; i++)
    {
        if (kill(descendants[i], signal) == 0) // send provided signal to all descendants
        {
            printf("%s ", action); // action is just what you want to call the signal and not the signal itself
            char name[256];
            char status[256];
            if (!read_status_field(descendants[i], "Name:", name))
            {
                strcpy(name, "unknown");
            }
            if (!read_status_field(descendants[i], "State:", status))
            {
                strcpy(status, "unknown");
            }
            printf("%s (%d) [%s]\n", name, descendants[i], status);
        }
        else
        {
            perror(action); // print the error in particular action
        }
    }
}

// Function to print all defunct descendant processes
void print_defunct_descendants(pid_t pid)
{
    pid_t descendants[MAX_ANCESTORS];
    int count = 0;
    get_all_descendants(pid, descendants, &count);

    if (count == 0)
    {
        printf("No descendants of process %d", pid);
        return;
    }

    pid_t defunct_desc[MAX_ANCESTORS];
    int defunct_count = 0;

    // Store defunct descendants in defunct_desc array
    for (int i = 0; i < count; i++)
    {
        if (is_defunct(descendants[i]))
        {
            defunct_desc[defunct_count++] = descendants[i];
        }
    }

    // Print defunct descendants
    if (defunct_count == 0)
    {
        printf("There are no defunct descendents of PID: %d.\n", pid);
    }
    else
    {
        printf("Defunct descendents of PID: %d\n", pid);
        for (int i = 0; i < defunct_count; i++)
        {
            char name[256];
            char status[256];
            if (!read_status_field(defunct_desc[i], "Name:", name))
            {
                strcpy(name, "unknown");
            }
            if (!read_status_field(defunct_desc[i], "State:", status))
            {
                strcpy(status, "unknown");
            }
            printf("%s (%d) [%s]\n", name, defunct_desc[i], status);
        }
    }
}

// Function to print specific descendants (direct or non-direct)
void print_specific_descendants(pid_t pid, bool direct_only)
{
    pid_t descendants[MAX_ANCESTORS];
    int count = 0, direct_count = 0;
    pid_t direct_descendants[MAX_ANCESTORS];
    get_all_descendants(pid, descendants, &count);

    for (int i = 0; i < count; i++)
    {
        if (get_ppid(descendants[i]) == pid)
        {
            direct_descendants[direct_count++] = descendants[i];
        }
    }

    if (direct_only)
    {
        print_process_list("Direct descendants:", direct_descendants, direct_count);
    }
    else
    {
        int non_direct_count = 0;
        pid_t non_direct_descendants[MAX_ANCESTORS];

        for (int i = 0; i < count; i++)
        {
            bool is_direct = false;
            for (int j = 0; j < direct_count; j++)
            {
                if (descendants[i] == direct_descendants[j])
                {
                    is_direct = true;
                    break;
                }
            }
            if (!is_direct)
            {
                non_direct_descendants[non_direct_count++] = descendants[i];
            }
        }

        // Print non-direct descendants
        if (non_direct_count == 0)
        {
            printf("No non-direct descendants of PID: %d found.\n", pid);
        }
        else
        {
            printf("Non-direct descendants of PID %d:\n", pid);
            for (int i = 0; i < non_direct_count; i++)
            {
                char name[256];
                char status[256];
                if (!read_status_field(non_direct_descendants[i], "Name:", name))
                {
                    strcpy(name, "unknown");
                }
                if (!read_status_field(non_direct_descendants[i], "State:", status))
                {
                    strcpy(status, "unknown");
                }
                printf("%s (%d) [%s]\n", name, non_direct_descendants[i], status);
            }
        }
    }
}

// Function to print sibling processes
void print_siblings(pid_t pid, bool defunct_only)
{
    pid_t ppid = get_ppid(pid);
    if (ppid == -1)
    {
        printf("Failed to get parent PID for PID %d\n", pid);
        return;
    }

    DIR *dp;
    struct dirent *entry;
    Process process;

    if ((dp = opendir("/proc")) == NULL) // opens the /proc file
        return;

    pid_t siblings[MAX_ANCESTORS];
    int sibling_count = 0;

    while ((entry = readdir(dp)) != NULL)
    {
        if (entry->d_type == DT_DIR && atol(entry->d_name) > 0)
        {
            pid_t sibling_pid = atol(entry->d_name);                 // set the encountered pid as sibling
            if (sibling_pid != pid && get_ppid(sibling_pid) == ppid) // if sibling is not as self and sibling ppid match self ppid then its a sibling
            {
                get_process_details(sibling_pid, &process);

                if (!defunct_only || strcmp(process.status, "Z") == 0) // check for speciality check of defunct. If need only defunct then it will check for that
                {
                    siblings[sibling_count++] = process.pid;
                }
            }
        }
    }
    closedir(dp);

    if (sibling_count == 0)
    {
        printf("No %s siblings of PID %d found\n", defunct_only ? "defunct" : "", pid);
    }
    else
    {
        printf("%s siblings of PID %d:\n", defunct_only ? "Defunct" : "All", pid);
        for (int i = 0; i < sibling_count; i++)
        {
            char name[256];
            char status[256];
            if (!read_status_field(siblings[i], "Name:", name))
            {
                strcpy(name, "unknown");
            }
            if (!read_status_field(siblings[i], "State:", status))
            {
                strcpy(status, "unknown");
            }
            printf("%s (%d) [%s]\n", name, siblings[i], status);
        }
    }
}

// Function to print grandchildren processes
void print_grandchildren(pid_t pid)
{
    pid_t children[MAX_ANCESTORS];
    int children_count = 0;

    get_all_descendants(pid, children, &children_count);

    if (children_count == 0)
    {
        printf("No descendants of PID: %d found.\n", pid);
        return;
    }

    pid_t grandchildren[MAX_ANCESTORS * MAX_ANCESTORS];
    int grandchildren_count = 0;

    for (int i = 0; i < children_count; i++)
    {
        pid_t temp_grandchildren[MAX_ANCESTORS];
        int temp_grandchildren_count = 0;
        get_all_descendants(children[i], temp_grandchildren, &temp_grandchildren_count);
        for (int j = 0; j < temp_grandchildren_count; j++)
        {
            grandchildren[grandchildren_count++] = temp_grandchildren[j];
        }
    }

    if (grandchildren_count == 0)
    {
        printf("No grandchildren of PID: %d found.\n", pid);
    }
    else
    {
        printf("Grandchildren of PID %d:\n", pid);
        for (int i = 0; i < grandchildren_count; i++)
        {
            char name[256];
            char status[256];
            if (!read_status_field(grandchildren[i], "Name:", name))
            {
                strcpy(name, "unknown");
            }
            if (!read_status_field(grandchildren[i], "State:", status))
            {
                strcpy(status, "unknown");
            }
            printf("%s (%d) [%s]\n", name, grandchildren[i], status);
        }
    }
}

// Function to kill parent processes of zombie processes
void kill_parents_of_zombies(pid_t pid)
{
    pid_t descendants[MAX_ANCESTORS];
    int count = 0;

    get_all_descendants(pid, descendants, &count);

    if (count == 0)
    {
        printf("No descendants of PID: %d found\n", pid);
    }

    for (int i = 0; i < count; i++)
    {
        if (is_defunct(descendants[i]))
        {
            pid_t parent_pid = get_ppid(descendants[i]);
            if (kill(parent_pid, SIGKILL) == 0)
            {
                printf("Killed parent process %d of defunct process %d\n", parent_pid, descendants[i]);
            }
            else
            {
                perror("kill");
            }
        }
    }
}

int print_usage(char *p_name)
{
    printf("\nUsage: %s [-option] [root_process] [process_id]\n", p_name);
    printf("\nNOTE: The [-option] is optional. The program can run without that.\n");
    printf("\nAvailable options:\n-dx Kills all descendants of root process\n-dt Stops all descendants of root process\n-dc Continues all descendants of root_process\n-rp Kills process_id\n-nd List non direct descendants of process_id\n-dd List direct descendants of process_id\n-sb List siblings of process_id\n-bz List defunct siblings of process_id\n-zd List defunct descendants of process_id\n-gc List grandchildren of process_id\n-sz Shows if process_id is defunct or not\n-kz Kills the parent of any descendant of process_id\n");
    return EXIT_FAILURE;
}

// Main function to handle command-line arguments and execute corresponding actions
int main(int argc, char *argv[])
{
    if (argc < 3 || argc > 4)
    {
        print_usage(argv[0]);
    }

    if (argc == 3)
    {
        pid_t root_pid = atol(argv[1]);
        pid_t process_pid = atol(argv[2]);
        if (root_pid <= 0 || process_pid <= 0)
        {
            printf("Invalid process id\n");
            return EXIT_FAILURE;
        }
        if (!is_descendant(1, root_pid))
        {
            printf("Invalid root process. Process not in process tree\n");
            printf("%d is not a descendant of %d\n", root_pid, 1);
            return EXIT_FAILURE;
        }
        if (!is_descendant(1, process_pid))
        {
            printf("Invalid process_id. Process not in process tree\n");
            printf("%d is not a descendant of %d\n", process_pid, 1);
            return EXIT_FAILURE;
        }
        if (!is_descendant(root_pid, process_pid))
        {
            printf("%d is not a descendant of %d\n", process_pid, root_pid);
            return EXIT_FAILURE;
        }
        Process process;
        get_process_details(process_pid, &process);
        printf("\nProcess: %s\nPID: %d\nPPID: %d\nStatus: [%s]\n\n", process.name, process.pid, process.ppid, process.status);
        return EXIT_SUCCESS;
    }
    if (argc == 4)
    {
        char *option = argv[1];
        pid_t root_pid = atol(argv[2]);
        pid_t process_pid = atol(argv[3]);
        if (root_pid <= 0 || process_pid <= 0)
        {
            printf("\nInvalid process id\n");
            return EXIT_FAILURE;
        }
        if (!is_descendant(1, root_pid))
        {
            printf("Invalid root process. Process not in process tree");
            printf("\n%d is not a descendant of %d\n", root_pid, 1);
            return EXIT_FAILURE;
        }
        if (!is_descendant(1, process_pid))
        {
            printf("Invalid process_id. Process not in process tree");
            printf("\n%d is not a descendant of %d\n", process_pid, 1);
            return EXIT_FAILURE;
        }
        if (!is_descendant(root_pid, process_pid))
        {
            printf("\n%d is not a descendant of %d\n", process_pid, root_pid);
            return EXIT_FAILURE;
        }
        if (strcmp(option, "-dx") == 0)
            signal_all_descendants(root_pid, SIGKILL, "Killed");
        else if (strcmp(option, "-dt") == 0)
            signal_all_descendants(root_pid, SIGSTOP, "Stopped");
        else if (strcmp(option, "-dc") == 0)
            signal_all_descendants(root_pid, SIGCONT, "Continued");
        else if (strcmp(option, "-rp") == 0)
            kill(process_pid, SIGKILL) == 0 ? printf("Killed Process %d\n", process_pid) : perror("kill");
        else if (strcmp(option, "-nd") == 0)
            print_specific_descendants(process_pid, false);
        else if (strcmp(option, "-dd") == 0)
            print_specific_descendants(process_pid, true);
        else if (strcmp(option, "-sb") == 0)
            print_siblings(process_pid, false);
        else if (strcmp(option, "-bz") == 0)
            print_siblings(process_pid, true);
        else if (strcmp(option, "-zd") == 0)
            print_defunct_descendants(process_pid);
        else if (strcmp(option, "-gc") == 0)
            print_grandchildren(process_pid);
        else if (strcmp(option, "-sz") == 0)
            printf("Process %d is %sdefunct\n", process_pid, is_defunct(process_pid) ? "" : "not ");
        else if (strcmp(option, "-kz") == 0)
            kill_parents_of_zombies(process_pid);
        else
        {
            print_usage(argv[0]);
        }

        return EXIT_SUCCESS;
    }
}