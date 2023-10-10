/* Copyright (C) 2020 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata.h"
#include "util-daemon.h"
#include "util-debug.h"
#include <sys/wait.h>


static volatile sig_atomic_t sigflag = 0;

/**
 * \brief Signal handler used to take the parent process out of stand-by
 */
static void SignalHandlerSigusr1 (int signo)
{
    sigflag = 1;
}

/**
 * \brief Set the parent on stand-by until the child is ready
 *
 * \param pid pid of the child process to wait
 */
static int WaitForChild (pid_t pid)
{
    int status = 0;
    SCLogNotice("Parent waiting for child");
    /* Wait until child signals is ready */
    while (true) {
        if (waitpid(pid, &status, WNOHANG)) {
            /* Check if the child is still there, otherwise the parent should exit */
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                SCLogNotice("Child exited");
                return status;
            }
        }
        /* sigsuspend(); */
        sleep(1);
    }
    return status;
}

pid_t child_pid = 0;

int runChildProcess(int argc, char **argv) {
        /* Creates a new process */
        pid_t pid;
#if defined(OS_DARWIN) && defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif
    pid = fork();
#if defined(OS_DARWIN) && defined(__clang__)
#pragma clang diagnostic pop
#endif
    if (pid < 0) {
        /* Fork error */
        FatalError(SC_ERR_FATAL, "Error forking the process");
    } else if (pid == 0) {
       // SetupLogging();
        return SuricataMain(argc, argv);
    }
    child_pid = pid;
    // continue to wait for child in parent
    return WaitForChild (pid);
}

/**
 * \brief Check for a valid combination daemon/mode
 *
 * \param daemon daemon on or off
 * \param mode selected mode
 *
 * \retval 1 valid combination
 * \retval 0 invalid combination
 */
int CheckValidDaemonModesForChild (int mode)
{

    switch (mode) {
        case RUNMODE_PCAP_FILE:
            SCLogDebug("pcap offline mode ");
            return 0;
        case RUNMODE_UNITTEST:
            SCLogDebug("unittests");
            return 0;
        default:
            SCLogDebug("Allowed mode");
            break;
    }
    return 1;
}

/** Suricata instance */
extern SCInstance suricata;
extern void SCInstanceInit(SCInstance *suri, const char *progname);
extern TmEcode ParseCommandLine(int argc, char** argv, SCInstance *suri);
extern int FinalizeRunMode(SCInstance *suri, char **argv);

void Init(int argc, char **argv) {
    SCInstanceInit(&suricata, argv[0]);

    if (InitGlobal() != 0) {
        exit(EXIT_FAILURE);
    }

#ifdef OS_WIN32
    /* service initialization */
    if (WindowsInitService(argc, argv) != 0) {
        exit(EXIT_FAILURE);
    }
#endif /* OS_WIN32 */

    if (ParseCommandLine(argc, argv, &suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (FinalizeRunMode(&suricata, argv) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{

    /* Register the signal handler */
    signal(SIGUSR1, SignalHandlerSigusr1);
    signal(SIGTERM, SignalHandlerSigusr1);
    signal(SIGINT, SignalHandlerSigusr1);
    signal(SIGHUP, SignalHandlerSigusr1);
    Init(argc,argv);
    while(sigflag == 0) {
        if(runChildProcess(argc, argv) != 0) {
            // if not succefully exited then do not retry
            break;
        }
        if (CheckValidDaemonModesForChild(suricata.run_mode) == 0) {
            break;
        }
    }
    if(sigflag == 1) {
        kill(child_pid, SIGUSR1);
        WaitForChild (child_pid);
    }

    SCLogInfo("exiting");
}
