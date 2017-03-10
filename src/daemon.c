#define _GNU_SOURCE
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include "DaemonConfig.h"

#define PID_FILE "/tmp/daemon.pid"


struct config
{
    bool reload;
    bool stop;
    unsigned int counter;
};

static struct config configuration; 

static struct option long_options[] = 
{
    {"reload", no_argument, 0, 'r'},
    {"stop", no_argument, 0, 's'},
    {0, 0, 0, 0}
};


bool createPidFile(void)
{
    int fd = open(PID_FILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        syslog(LOG_NOTICE, "can't create pid file");
        return false;
    }
    char *p = NULL;
    int size = asprintf(&p, "%d", getpid());
    write(fd, p, size);
    close(fd);
    free(p);
    return true;
}

void removePidFile(void)
{
    remove(PID_FILE);
}

int readPidfromFile(void)
{
    int ret = -1;
    int fd = open(PID_FILE, O_RDONLY);
    if (fd < 0)
    {
        syslog(LOG_NOTICE, "reading PID, open failed");
        return ret;
    }
    char buf[10] = {0};
    ssize_t size = read(fd, buf, sizeof(buf));
    if (size < 0)
    {
        syslog(LOG_NOTICE, "reading PID, read failed");
        goto exit;
    }

    if(size < sizeof(buf))
    {
        // we were only expecting a PID in this file, 
        // and that fit into our buffer, assuming its
        // the right thing we read, and file is not corrupt
        // convert this buffer to a number
        ret = (int)strtol(buf, NULL, 10);
        syslog(LOG_NOTICE, "reading PID, success %d", ret);
    }
    else
    {
        syslog(LOG_NOTICE, "reading PID, read unexpected number of bytes");
    }
exit:
    close(fd);
    return ret;
}



void setuplogging(char *pName)
{
    openlog(pName, LOG_PID, LOG_USER);
}

void closelogging(void)
{
    closelog();
}

#define CONF_FILE "/tmp/daemon.conf"
void loadConfiguration(void)
{
    // default configuration
    configuration.counter = 10;

    FILE* fd = fopen(CONF_FILE, "r");
    if (fd == NULL)
    {
        syslog(LOG_NOTICE, "conf file open failed");
        return;
    }
    ssize_t readSize = 0;
    char *p = NULL;
    size_t n = 0;
    
    while((readSize = getline(&p, &n, fd)) != -1)
    {
        // we only expect a line counter=XX.
        // anything else is a corrupt conf file
        if (strncmp("counter=", p, strlen("counter=")) != 0)
        {
            syslog(LOG_NOTICE, "conf file has unknown content %s", p);
        }
        else
        {
            // find = sign in p
            char *pEqual = strstr(p, "=");
            if(pEqual)
            {
                configuration.counter = (int)strtoul(++pEqual, NULL, 10);
                syslog(LOG_NOTICE, "counter is %d", configuration.counter);
                // got what we wanted, even if there is anything else in the file
                // its gibberish for us.. so break out
                break;
            }
        }
       
        free(p);
        p = NULL;
        n = 0; 
    }
    free(p);
    p = NULL;
}

void printUsage(char *pName)
{
    printf("Usage : %s\n", pName);
    for(int i = 0; i < sizeof(long_options)/sizeof(struct option); i++)
    {
        if(long_options[i].name == 0)
            break;
        printf("\t %s \t", long_options[i].name);
        if (long_options[i].has_arg == no_argument)
            printf("\n");
        else if (long_options[i].has_arg == required_argument)
            printf("required_argument\n");
        else if (long_options[i].has_arg == optional_argument)
            printf("optional_argument\n");
    }
}

int validateArguments(int argc, char *argv[])
{
    int longindex, opt = -1;
    int ret = 0;
    while ((opt = getopt_long(argc, argv, "", long_options, &longindex)) != -1)
    {
        switch (opt)
        {
            case 'r':
                configuration.reload = true;
                break;
            case 's':
                configuration.stop = true;
                break;
            default:
                printUsage(argv[0]);
                ret = -1;
                break;
        }
    }
    return ret;
}

void signalHandler(int signum)
{
   switch (signum)
    {
        case SIGHUP:
            syslog(LOG_NOTICE, "got SIGHUP");
            loadConfiguration();
            syslog(LOG_NOTICE, "signal handler: counter is %d", configuration.counter);
            break;
        case SIGINT:
            syslog(LOG_NOTICE, "got SIGINT");
            removePidFile();
            syslog(LOG_NOTICE, "exiting");
            closelogging();
            // terminate the daemon 
            exit(EXIT_SUCCESS);
    }
}
int main(int argc, char *argv[])
{
    pid_t pid;
    int exitStatus = EXIT_FAILURE;
    setuplogging("daemon-parent");
    syslog(LOG_NOTICE, "starting version %d:%d",
            Daemon_VERSION_MAJOR, Daemon_VERSION_MINOR);

    // check arguments
    if (validateArguments(argc, argv) != 0)
        goto exit;

    // read the pid from file, and send a signal to running process
    int temp = readPidfromFile();
    if (temp != -1)
    {
        syslog(LOG_NOTICE, "instance already running");
        pid = temp;
        if (configuration.reload == true)
            kill(pid, SIGHUP);
        if (configuration.stop == true)
            kill(pid, SIGINT); 
        goto exit;
    }

    loadConfiguration();

    // the reason we fork is two-fold
    // 1. let the command invoking process be unblocked, 
    // example: if user launched the command from shell, 
    // then return the command prompt to the user. 
    //
    // 2. fork() creates a new process to run in the background
    // The process created is created from this process, and hence
    // the newly created process can't be the process group leader.
    // This is important later when we call setsid();
    pid = fork();
    if (pid < 0)
    {
        syslog(LOG_NOTICE, "fork failed, exiting");
        goto exit;
    }
    else if (pid > 0)
    {
        // parent, work done, exit
        syslog(LOG_NOTICE, "exiting");
        exitStatus = EXIT_SUCCESS;
        goto exit;
    }
    else // pid == 0, child
    {
        closelogging();
        setuplogging("daemon-child-1");
        syslog(LOG_NOTICE, "executing");

        // sanitize the environment before starting our work
        // this sanitization process is a bit involved
        //
        // First, change the session id of this process.
        // This is bcos we want the daemon to continue to run even if the user
        // logged off and terminates a session, so lets create a new session
        // for this process, so that it can continue to run. 

        // Its important to note here that the setsid() is called from child
        // created by fork(), this is to ensure that the setsid() is called
        // from a process which is NOT process group leader. This ensures
        // that setsid() will create a new session, and this child process
        // is now the session group leader. This also creates a new process
        // group, with this process as the process group leader
        if (setsid() == -1)
        {
            syslog(LOG_NOTICE, "setsid failed");
            goto exit;
        }

        // at this point, we are not tied to the session, and are running in
        // a new session with no terminal. But there is a problem.
        // We are running as the session group leader. As a session group
        // leader with no terminal, if our process was to open a terminal
        // device, then that device automatically becomes the controlling
        // terminal. But we don't want this accidental terminal to showup.
        //
        // Easy solution : fork() again, since we forked from session group
        // leader, the new process created won't be the session group. We
        // will let the current process die.
        //
        // Dont worry about SIGHUP being generated for the new child being
        // created because of the current process exiting. Linux docs
        // mention that SIGHUP is sent to all foreground processes when
        // session group leader exits. But the new process being created
        // will not be a foreground process, so it won't receive SIGHUP.
        //
        // NOTE : this is validated by runtime verification. On Fedora, 
        // child didnt get SIGHUP
        //
        // Here's the basis of this special case, although as mentioned
        // above, seems this doesn't apply anymore
        // But there's a catch here. The current process will die, but its
        // session group leader. If it dies, the new process being created
        // will get a SIGHUP and it will die too. So we want to handle
        // SIGHUP before we fork. In our handler, we need to be able to
        // absorb the 1st SIGHUP that will be delivered to us.

                
        // lets fork
        pid = fork();
        if (pid < 0)
        {
            syslog(LOG_NOTICE, "fork failed");
            goto exit;
        }
        else if (pid > 0)
        {
            // parent process
            syslog(LOG_NOTICE, "forked, exiting");
            exitStatus = EXIT_SUCCESS;
            goto exit;
        }
        else // pid == 0
        {
            closelogging();
            setuplogging("daemon-child-2");
            syslog(LOG_NOTICE, "executing");

            struct sigaction sa;

            sa.sa_handler = signalHandler;
            sigemptyset(&sa.sa_mask);
            sigaddset(&sa.sa_mask, SIGCHLD);  /* ignore child - i.e. we don't need to wait for it */
            sigaddset(&sa.sa_mask, SIGTSTP);  /* ignore Tty stop signals */
            sigaddset(&sa.sa_mask, SIGTTOU);  /* ignore Tty background writes */
            sigaddset(&sa.sa_mask, SIGTTIN);  /* ignore Tty background reads */

            sigaction(SIGHUP, &sa, NULL);     /* catch hangup signal */
            sigaction(SIGINT, &sa, NULL);     /* catch int signal */

            // This completes the first stage of sanitization, lets move
            // to other steps
            //
            
            //set umask to 0, to take control of all our files
            umask(0);

            // close STDIN, STDERR, STDOUT (or map them to logfiles,
            // not doing it here, since using syslog for logging)
            //
            close(STDERR_FILENO);
            close(STDIN_FILENO);
            close(STDOUT_FILENO);

            // change the pwd to something reasonable. Lets change it to /
            chdir("/");

            // drop privileges, dont continue to run as root
            if (getuid() == 0)
            {
                syslog(LOG_NOTICE, "running as root");
            }

            // create a file to hold our PID, to make sure only one
            // instance is running
            if (createPidFile() == false)
            {
                syslog(LOG_NOTICE, "failed to create PID file");
                goto exit;
            }

            // now we are ready to do out real work
            syslog(LOG_NOTICE, "counter is %d", configuration.counter);
            while (true)
            {
                // sleep for 5 seconds
                sleep(5);
            }
        }
    }
    exitStatus = EXIT_SUCCESS;
    removePidFile();
exit:
    syslog(LOG_NOTICE, "exiting");
    closelogging();
    exit(exitStatus);
}
