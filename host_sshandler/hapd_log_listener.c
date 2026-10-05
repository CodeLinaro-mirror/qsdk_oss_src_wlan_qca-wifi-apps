/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 *
 * hapd_log_listener - direct Unix socket receiver for host_sshandler.
 *
 * hostapd sends a datagram to HAPD_SSH_SOCK_PATH on every connection
 * failure event.  Normal wire format: "<event> <mac> <iface>".
 * Crash wire format: "hostapd_crash <pid> <signal> <executable>".
 *
 * On trigger, per-event hostapd_cli commands enable BSS-scope per-module
 * verbose logging (LOG_LEVEL <module> debug_verbose) and install a peer
 * filter (LOG_PEER <mac>) for the failing STA.
 *
 * The ss_handler core maintains a dedicated 2-minute hostapd log window.
 * The first accepted event starts the deadline; expiry restores log levels
 * and clears the peer filters even if more failures arrive meanwhile.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include "subsys_core.h"
#include "hapd_log_listener.h"

#ifndef HAPD_CLI_CMD
#define HAPD_CLI_CMD "hostapd_cli"
#endif

#define MAX_MAC_LEN           18
#define MAX_PEER_LOG_ENTRIES  32  /* cap against MAC flood DoS */
#define HAPD_CRASH_QUEUE_SIZE 4

/*
 * Bitmask of hostapd modules that may be overridden by any event action.
 * Must stay in sync with event_action_table below.
 */
#define MOD_IEEE80211  (1U << 0)
#define MOD_IEEE8021X  (1U << 1)
#define MOD_MLME       (1U << 2)
#define MOD_DRIVER     (1U << 3)

/*
 * Per-event hostapd_cli command dispatch table.
 * mod_bit: which MOD_* flag this command sets (0 if none).
 * with_peer: append peer MAC as the command argument.
 */
struct hapd_event_cmd {
	const char *cmd;
	uint32_t    mod_bit;
	bool        with_peer;
};

struct hapd_event_action {
	const char                  *event;
	const struct hapd_event_cmd *cmds;
};

/* Active peer log entries — one per (iface, addr) pair. */
struct hapd_peer_log_entry {
	char     iface[HAPD_IFACE_LEN];
	char     addr[MAX_MAC_LEN];
	uint32_t mod_mask;  /* OR of MOD_* flags set for this entry */
	struct hapd_peer_log_entry *next;
};

static struct hapd_peer_log_entry *g_peer_log_list;
static int                         g_peer_log_count;
static pthread_mutex_t g_peer_log_lock = PTHREAD_MUTEX_INITIALIZER;

struct hapd_crash_queue {
	struct hapd_crash_info jobs[HAPD_CRASH_QUEUE_SIZE];
	size_t head;
	size_t tail;
	size_t count;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

static struct hapd_crash_queue g_crash_queue = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
};
static pthread_t hapd_crash_worker_thread;

/* Module name strings must match hostapd_mod_str_to_idx() in hostapd_log.c */
static const struct { uint32_t bit; const char *name; } mod_names[] = {
	{ MOD_IEEE80211, "ieee80211" },
	{ MOD_IEEE8021X, "ieee8021x" },
	{ MOD_MLME,      "mlme"      },
	{ MOD_DRIVER,    "driver"    },
};
#define MOD_NAMES_COUNT (sizeof(mod_names) / sizeof(mod_names[0]))

/*
 * next_token - extract one space-delimited token from a message string.
 *
 * Parses the wire format datagram: "<event> <mac> <iface>"
 * e.g. "4way_fail aa:bb:cc:dd:ee:ff phy00.1-0"
 *
 * Finds the next space in *src, NUL-terminates the token there, copies it
 * into dst (up to dst_size bytes), and advances *src past the space so the
 * next call starts at the following field.
 *
 * Returns 0 on success, -1 if the token is missing or too long for dst.
 * Note: modifies the source string in place (NUL-terminates at the space).
 */
static int next_token(char **src, char *dst, size_t dst_size)
{
	char *end = strchr(*src, ' ');

	if (!end)
		return -1;
	*end = '\0';
	if (strlcpy(dst, *src, dst_size) >= dst_size)
		return -1;
	*src = end + 1;
	return 0;
}

static bool crash_executable_is_safe(const char *s)
{
	if (!s || !*s)
		return false;

	for (; *s; s++) {
		if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') || *s == '.' || *s == '-' ||
		    *s == '_')
			continue;
		return false;
	}

	return true;
}

static int parse_crash_number(const char *s, unsigned long max,
				      unsigned long *value)
{
	char *end;
	unsigned long parsed;

	if (!s || !*s || !value)
		return -1;

	errno = 0;
	parsed = strtoul(s, &end, 10);
	if (errno || end == s || *end || parsed == 0 || parsed > max)
		return -1;

	*value = parsed;
	return 0;
}

/*
 * Parse the hostapd crash wire format.  Return 1 for a crash event, 0 when
 * the datagram is a normal hostapd event, and -1 for a malformed crash event.
 */
static int parse_hostapd_crash_event(char *msg, struct hapd_crash_info *info)
{
	char event[32];
	char pid_str[24];
	char signal_str[24];
	char *p;
	char *separator;
	unsigned long pid;
	unsigned long signal_number;
	int ret;

	if (!msg || !info)
		return -1;

	p = msg;
	if (next_token(&p, event, sizeof(event)) < 0)
		return 0;
	if (strcmp(event, HAPD_CRASH_EVENT) != 0)
		return 0;

	if (next_token(&p, pid_str, sizeof(pid_str)) < 0)
		return -1;

	separator = strchr(p, ' ');
	if (separator) {
		*separator = '\0';
		if (strlcpy(signal_str, p, sizeof(signal_str)) >=
		    sizeof(signal_str))
			return -1;
		p = separator + 1;
	} else {
		if (strlcpy(signal_str, p, sizeof(signal_str)) >=
		    sizeof(signal_str))
			return -1;
		p = NULL;
	}

	ret = parse_crash_number(pid_str, (unsigned long)INT_MAX, &pid);
	if (ret < 0 || parse_crash_number(signal_str, (unsigned long)NSIG,
					  &signal_number) < 0)
		return -1;

	memset(info, 0, sizeof(*info));
	info->pid = (pid_t)pid;
	info->signal = (int)signal_number;
	if (p && *p) {
		if (strlcpy(info->executable, p,
			    sizeof(info->executable)) >= sizeof(info->executable) ||
		    !crash_executable_is_safe(info->executable))
			return -1;
	} else {
		strlcpy(info->executable, "hostapd", sizeof(info->executable));
	}

	return 1;
}

static void queue_hostapd_crash(const struct hapd_crash_info *info)
{
	pthread_mutex_lock(&g_crash_queue.lock);
	if (g_crash_queue.count >= HAPD_CRASH_QUEUE_SIZE) {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-crash]: queue full, dropping pid=%ld signal=%d",
		       (long)info->pid, info->signal);
		pthread_mutex_unlock(&g_crash_queue.lock);
		return;
	}

	g_crash_queue.jobs[g_crash_queue.tail] = *info;
	g_crash_queue.tail = (g_crash_queue.tail + 1) % HAPD_CRASH_QUEUE_SIZE;
	g_crash_queue.count++;
	pthread_cond_signal(&g_crash_queue.cond);
	pthread_mutex_unlock(&g_crash_queue.lock);
}

static void *hapd_crash_worker(void *arg)
{
	(void)arg;

	for (;;) {
		struct hapd_crash_info info;

		pthread_mutex_lock(&g_crash_queue.lock);
		while (g_crash_queue.count == 0)
			pthread_cond_wait(&g_crash_queue.cond, &g_crash_queue.lock);

		info = g_crash_queue.jobs[g_crash_queue.head];
		g_crash_queue.head =
			(g_crash_queue.head + 1) % HAPD_CRASH_QUEUE_SIZE;
		g_crash_queue.count--;
		pthread_mutex_unlock(&g_crash_queue.lock);

		syslog(LOG_INFO,
		       "HOST_SSHANDLER [hapd-crash]: collecting pid=%ld signal=%d executable=%s",
		       (long)info.pid, info.signal, info.executable);
		subsys_action_hostapd_crash_snapshot(&info);
	}

	return NULL;
}

/* Validate iface: [a-zA-Z0-9._-] only. */
static int iface_is_safe(const char *s)
{
	if (!s || !*s)
		return 0;
	for (; *s; s++) {
		if ((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		    (*s >= '0' && *s <= '9') ||
		    *s == '.' || *s == '_' || *s == '-')
			continue;
		return 0;
	}
	return 1;
}

/* Validate addr: MAC format xx:xx:xx:xx:xx:xx, hex digits and colons only. */
static int mac_is_safe(const char *s)
{
	if (!s || strlen(s) != 17)
		return 0;
	for (; *s; s++) {
		if ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') ||
		    (*s >= 'A' && *s <= 'F') || *s == ':')
			continue;
		return 0;
	}
	return 1;
}

static void peer_log_add(const char *iface, const char *addr, uint32_t mod_mask)
{
	struct hapd_peer_log_entry *e;

	pthread_mutex_lock(&g_peer_log_lock);
	for (e = g_peer_log_list; e; e = e->next) {
		if (strcmp(e->iface, iface) == 0 && strcmp(e->addr, addr) == 0) {
			e->mod_mask |= mod_mask;
			pthread_mutex_unlock(&g_peer_log_lock);
			return;
		}
	}
	if (g_peer_log_count >= MAX_PEER_LOG_ENTRIES) {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: peer table full count=%d, dropping iface=%s addr=%s",
		       g_peer_log_count, iface, addr);
		pthread_mutex_unlock(&g_peer_log_lock);
		return;
	}
	e = calloc(1, sizeof(*e));
	if (e) {
		strlcpy(e->iface, iface, sizeof(e->iface));
		strlcpy(e->addr, addr, sizeof(e->addr));
		e->mod_mask = mod_mask;
		e->next = g_peer_log_list;
		g_peer_log_list = e;
		g_peer_log_count++;
	} else {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: peer allocation failed iface=%s addr=%s",
		       iface, addr);
	}
	pthread_mutex_unlock(&g_peer_log_lock);
}

static void run_cli(const char *cmd)
{
	int status;
	FILE *p = popen(cmd, "r");

	if (!p) {
		syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: popen failed errno=%d: %s",
		       errno, strerror(errno));
		return;
	}
	status = pclose(p);
	if (status < 0) {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: pclose failed cmd=[%s] errno=%d: %s",
		       cmd, errno, strerror(errno));
	} else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status))
			syslog(LOG_ERR,
			       "HOST_SSHANDLER [hapd-log]: command exited status=%d cmd=[%s]",
			       WEXITSTATUS(status), cmd);
	} else if (WIFSIGNALED(status)) {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: command killed signal=%d cmd=[%s]",
		       WTERMSIG(status), cmd);
	} else {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: command returned raw status=0x%x cmd=[%s]",
		       status, cmd);
	}
}

/*
 * Restore all per-module log levels and clear peer filters for every
 * tracked iface/peer pair when the dedicated hostapd log window expires.
 *
 * Snapshots the list under the lock then releases it before calling popen,
 * so peer_log_add() is not blocked during CLI execution.
 */
void hapd_log_listener_clear_all_peers(void)
{
	struct hapd_peer_log_entry *list, *e, *tmp;
	char cmd[256];
	size_t i;

	pthread_mutex_lock(&g_peer_log_lock);
	list = g_peer_log_list;
	g_peer_log_list = NULL;
	g_peer_log_count = 0;
	pthread_mutex_unlock(&g_peer_log_lock);

	e = list;
	while (e) {
		for (i = 0; i < MOD_NAMES_COUNT; i++) {
			if (!(e->mod_mask & mod_names[i].bit))
				continue;
			snprintf(cmd, sizeof(cmd),
				 HAPD_CLI_CMD " -i %s LOG_LEVEL %s default 2>&1",
				 e->iface, mod_names[i].name);
			run_cli(cmd);
		}
		snprintf(cmd, sizeof(cmd),
			 HAPD_CLI_CMD " -i %s LOG_LEVEL INFO 2>&1", e->iface);
		run_cli(cmd);
		snprintf(cmd, sizeof(cmd),
			 HAPD_CLI_CMD " -i %s LOG_PEER clear 2>&1", e->iface);
		run_cli(cmd);

		tmp = e->next;
		free(e);
		e = tmp;
	}
}

/*
 * Per-event command tables.
 *
 * auth_reject:  ieee80211 + mlme verbose, peer filter
 * assoc_reject: ieee80211 + mlme verbose, peer filter, STATUS dump
 * 4way_fail:    ieee8021x verbose, peer filter, MIB dump
 *
 * LOG_LEVEL <module> debug_verbose targets the BSS-scope per-module
 * override only — other modules and other BSSes are unaffected.
 */
static const struct hapd_event_cmd auth_reject_cmds[] = {
	{ "LOG_LEVEL ieee80211 debug_verbose", MOD_IEEE80211, false },
	{ "LOG_LEVEL mlme debug_verbose",      MOD_MLME,      false },
	{ "LOG_PEER",                          0,             true  },
	{ NULL }
};

static const struct hapd_event_cmd assoc_reject_cmds[] = {
	{ "LOG_LEVEL ieee80211 debug_verbose", MOD_IEEE80211, false },
	{ "LOG_LEVEL mlme debug_verbose",      MOD_MLME,      false },
	{ "LOG_PEER",                          0,             true  },
	{ "STATUS",                            0,             false },
	{ NULL }
};

static const struct hapd_event_cmd eapol_fail_cmds[] = {
	{ "LOG_LEVEL ieee8021x debug_verbose", MOD_IEEE8021X, false },
	{ "LOG_PEER",                          0,             true  },
	{ "MIB",                               0,             false },
	{ NULL }
};

static const struct hapd_event_cmd connectivity_fail_cmds[] = {
	{ "LOG_LEVEL ieee80211 debug_verbose", MOD_IEEE80211, false },
	{ "LOG_LEVEL driver debug_verbose",    MOD_DRIVER,    false },
	{ "LOG_PEER",                          0,             true  },
	{ "STATUS",                            0,             false },
	{ NULL }
};

/*
 * vap_create_fail / vap_up_fail: BSS-level events (NULL addr).
 * Enable driver module verbose logging and dump STATUS for the BSS.
 */
static const struct hapd_event_cmd vap_create_fail_cmds[] = {
	{ "LOG_LEVEL driver debug_verbose", MOD_DRIVER, false },
	{ "STATUS",                         0,          false },
	{ NULL }
};

static const struct hapd_event_cmd vap_up_fail_cmds[] = {
	{ "LOG_LEVEL driver debug_verbose", MOD_DRIVER, false },
	{ "STATUS",                         0,          false },
	{ NULL }
};

static const struct hapd_event_action event_action_table[] = {
	{ "auth_reject",      auth_reject_cmds      },
	{ "assoc_reject",     assoc_reject_cmds     },
	{ "4way_fail",        eapol_fail_cmds       },
	{ "auth_tx_fail",     connectivity_fail_cmds },
	{ "assoc_resp_tx_fail", connectivity_fail_cmds },
	{ "reassoc_resp_tx_fail", connectivity_fail_cmds },
	{ "probe_resp_tx_fail", connectivity_fail_cmds },
	{ "deauth_tx_fail",   connectivity_fail_cmds },
	{ "disassoc_tx_fail", connectivity_fail_cmds },
	{ "action_tx_fail",   connectivity_fail_cmds },
	{ "vap_create_fail",  vap_create_fail_cmds  },
	{ "vap_up_fail",      vap_up_fail_cmds      },
	{ NULL }
};

static const struct hapd_event_action *find_event_action(const char *event)
{
	const struct hapd_event_action *a;

	for (a = event_action_table; a->event; a++) {
		if (strcmp(a->event, event) == 0)
			return a;
	}
	return NULL;
}

static uint32_t event_type_to_bit(const char *ev)
{
	if (!ev || !*ev)                          return 0;
	if (!strcmp(ev, "auth_reject"))           return HAPD_TRIG_AUTH_REJECT;
	if (!strcmp(ev, "assoc_reject"))          return HAPD_TRIG_ASSOC_REJECT;
	if (!strcmp(ev, "4way_fail"))             return HAPD_TRIG_EAPOL_FAIL;
	if (!strcmp(ev, "vap_create_fail"))       return HAPD_TRIG_VAP_CREATE_FAIL;
	if (!strcmp(ev, "vap_up_fail"))           return HAPD_TRIG_VAP_UP_FAIL;
	if (!strcmp(ev, "auth_tx_fail"))          return HAPD_TRIG_AUTH_TX_FAIL;
	if (!strcmp(ev, "assoc_resp_tx_fail"))    return HAPD_TRIG_ASSOC_RESP_TX_FAIL;
	if (!strcmp(ev, "reassoc_resp_tx_fail"))  return HAPD_TRIG_REASSOC_RESP_TX_FAIL;
	if (!strcmp(ev, "probe_resp_tx_fail"))    return HAPD_TRIG_PROBE_RESP_TX_FAIL;
	if (!strcmp(ev, "deauth_tx_fail"))        return HAPD_TRIG_DEAUTH_TX_FAIL;
	if (!strcmp(ev, "disassoc_tx_fail"))      return HAPD_TRIG_DISASSOC_TX_FAIL;
	if (!strcmp(ev, "action_tx_fail"))        return HAPD_TRIG_ACTION_TX_FAIL;
	return 0;
}

static bool event_triggers_snapshot(const char *event)
{
	return !strcmp(event, "auth_reject") ||
	       !strcmp(event, "assoc_reject") ||
	       !strcmp(event, "4way_fail") ||
	       !strcmp(event, "vap_create_fail") ||
	       !strcmp(event, "vap_up_fail");
}

static const char *event_cloud_name(const char *event)
{
	if (!strcmp(event, "auth_tx_fail"))
		return "host_auth_tx_fail";
	if (!strcmp(event, "assoc_resp_tx_fail"))
		return "host_assoc_resp_tx_fail";
	if (!strcmp(event, "reassoc_resp_tx_fail"))
		return "host_reassoc_resp_tx_fail";
	if (!strcmp(event, "probe_resp_tx_fail"))
		return "host_probe_resp_tx_fail";
	if (!strcmp(event, "deauth_tx_fail"))
		return "host_deauth_tx_fail";
	if (!strcmp(event, "disassoc_tx_fail"))
		return "host_disassoc_tx_fail";
	if (!strcmp(event, "action_tx_fail"))
		return "host_action_tx_fail";
	return NULL;
}

static enum ath12k_crit_err_type event_snapshot_trigger(const char *event)
{
	if (!strcmp(event, "vap_create_fail") ||
	    !strcmp(event, "vap_up_fail"))
		return ATH12K_CRIT_VAP_BRINGUP;

	return ATH12K_CRIT_CONNECTION_FAIL;
}

/*
 * Dispatch per-event CLI commands: set per-module verbose level and install
 * peer filter.  Returns OR of all MOD_* bits set so the caller can record
 * which modules need to be restored at clear time.
 */
static uint32_t dispatch_event_cmds(const struct hapd_event_action *act,
				    const char *iface, const char *addr)
{
	const struct hapd_event_cmd *c;
	char cli_cmd[256];
	uint32_t mod_mask = 0;

	snprintf(cli_cmd, sizeof(cli_cmd),
		 HAPD_CLI_CMD " -i %s LOG_LEVEL EXCESSIVE 2>&1", iface);
	run_cli(cli_cmd);
	for (c = act->cmds; c->cmd; c++) {
		if (c->with_peer)
			snprintf(cli_cmd, sizeof(cli_cmd),
				 HAPD_CLI_CMD " -i %s %s %s 2>&1",
				 iface, c->cmd, addr);
		else
			snprintf(cli_cmd, sizeof(cli_cmd),
				 HAPD_CLI_CMD " -i %s %s 2>&1",
				 iface, c->cmd);
		run_cli(cli_cmd);
		mod_mask |= c->mod_bit;
	}
	return mod_mask;
}

static int listener_bind(void)
{
	struct sockaddr_un sa;
	struct stat st;
	int ret;
	int fd;

	ret = unlink(HAPD_SSH_SOCK_PATH);
	if (ret < 0 && errno != ENOENT)
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: unlink(%s) failed errno=%d: %s",
		       HAPD_SSH_SOCK_PATH, errno, strerror(errno));

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: socket() failed errno=%d: %s",
		       errno, strerror(errno));
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", HAPD_SSH_SOCK_PATH);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: bind(%s) failed errno=%d: %s",
		       HAPD_SSH_SOCK_PATH, errno, strerror(errno));
		close(fd);
		return -1;
	}

	if (chmod(HAPD_SSH_SOCK_PATH, 0622) < 0) {
		syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: chmod failed errno=%d: %s",
		       errno, strerror(errno));
	}
	if (stat(HAPD_SSH_SOCK_PATH, &st) < 0) {
		syslog(LOG_ERR,
		       "HOST_SSHANDLER [hapd-log]: stat(%s) failed errno=%d: %s",
		       HAPD_SSH_SOCK_PATH, errno, strerror(errno));
	}

	return fd;
}

/*
 * Listener thread — runs for the lifetime of the process.
 *
 * The thread starts unconditionally at init so it is ready to receive
 * the trigger datagram the instant hostapd sends it.  Starting on demand
 * (e.g. only after a connection failure) would race with the event itself.
 *
 * The core's periodic window updater performs cleanup after two minutes.
 */
void *subsys_hapd_listener_thread(void *arg)
{
	struct subsys_ctx *subsys = arg;
	struct hapd_listener_ctx *ctx = &subsys->hapd_log_ctx;
	char msg[HAPD_SSH_MSG_MAX];
	char addr[MAX_MAC_LEN], iface[HAPD_IFACE_LEN], event_str[32];

	openlog("HOST_SSHANDLER", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	while (!t_stop_flag) {
		int fd = listener_bind();
		if (fd < 0) {
			syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: bind failed, retry in 5s");
			sleep(5);
			continue;
		}

		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		while (!t_stop_flag) {
			pfd.revents = 0;

			int pr = poll(&pfd, 1, -1);
			if (pr < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: poll errno=%d: %s",
				       errno, strerror(errno));
				hapd_log_listener_clear_all_peers();
				break;
			}

			if (!(pfd.revents & POLLIN))
				continue;

			ssize_t n = recv(fd, msg, sizeof(msg) - 1, 0);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: recv errno=%d: %s",
				       errno, strerror(errno));
				hapd_log_listener_clear_all_peers();
				break;
			}
			if (n == 0)
				continue;
			msg[n] = '\0';

			{
				char crash_msg[HAPD_SSH_MSG_MAX];
				struct hapd_crash_info crash_info;
				int crash_ret;

				strlcpy(crash_msg, msg, sizeof(crash_msg));
				crash_ret = parse_hostapd_crash_event(crash_msg,
								      &crash_info);
				if (crash_ret < 0) {
					syslog(LOG_ERR,
					       "HOST_SSHANDLER [hapd-crash]: malformed: [%s]",
					       msg);
					continue;
				}
				if (crash_ret > 0) {
					queue_hostapd_crash(&crash_info);
					continue;
				}
			}

			event_str[0] = addr[0] = iface[0] = '\0';
			{
				/* Work on a copy so the error log can print the original. */
				char buf[HAPD_SSH_MSG_MAX];
				char *p = buf;
				strlcpy(buf, msg, sizeof(buf));

				if (next_token(&p, event_str, sizeof(event_str)) < 0 ||
				    next_token(&p, addr, sizeof(addr)) < 0 ||
				    strlcpy(iface, p, sizeof(iface)) >= sizeof(iface) ||
				    !iface[0]) {
					syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: malformed: [%s]", msg);
					continue;
				}
			}

			if (!iface_is_safe(iface) || !mac_is_safe(addr)) {
				syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: unsafe input rejected");
				continue;
			}

			uint32_t bit = event_type_to_bit(event_str);
			if (ctx->trigger_mask != HAPD_TRIG_ALL &&
			    bit != 0 && !(ctx->trigger_mask & bit))
				continue;

			const struct hapd_event_action *act = find_event_action(event_str);
			if (!act) {
				syslog(LOG_ERR, "HOST_SSHANDLER [hapd-log]: unknown event: [%s]", event_str);
				continue;
			}

			subsys_start_hapd_log_window(subsys);
			uint32_t mod_mask = dispatch_event_cmds(act, iface, addr);
			peer_log_add(iface, addr, mod_mask);

			const char *cloud_name = event_cloud_name(event_str);
			if (event_triggers_snapshot(event_str) || cloud_name) {
				char *snapshot_context[] = {
					SS_SNAP_KEY_SYSLOG,
					NULL
				};

				if (cloud_name)
					subsys_action_hostapd_connectivity_snapshot(
							cloud_name, snapshot_context);
				else
					subsys_action_start(SS_ACTION_SNAPSHOT, 0,
							    snapshot_context,
							    event_snapshot_trigger(event_str));
			}
		}

		if (close(fd) < 0)
			syslog(LOG_ERR,
			       "HOST_SSHANDLER [hapd-log]: close fd=%d failed errno=%d: %s",
			       fd, errno, strerror(errno));
		if (unlink(HAPD_SSH_SOCK_PATH) < 0 && errno != ENOENT)
			syslog(LOG_ERR,
			       "HOST_SSHANDLER [hapd-log]: cleanup unlink failed errno=%d: %s",
			       errno, strerror(errno));
	}

	return NULL;
}

static pthread_t hapd_listener_thread;

void host_start_hapd_listener_thread(struct subsys_ctx *ctx)
{
	int ret;

	ctx->hapd_log_ctx.trigger_mask = ctx->cfg.hapd_log_trigger_mask;
	ret = pthread_create(&hapd_crash_worker_thread, NULL,
			     hapd_crash_worker, NULL);
	if (ret != 0) {
		fprintf(stderr,
			"HOST_SSHANDLER [hapd-crash]: failed to start worker: %s (%d)\n",
			strerror(ret), ret);
	}

	ret = pthread_create(&hapd_listener_thread, NULL,
			     subsys_hapd_listener_thread, ctx);
	if (ret != 0) {
		fprintf(stderr,
			"HOST_SSHANDLER [hapd-log]: failed to start listener: %s (%d)\n",
			strerror(ret), ret);
	}
}
