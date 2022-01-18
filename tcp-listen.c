/**
 * Tool that allows to determine which port are avalaible and not filtered on a
 * remote system.
 *
 * For instance, we have access to a remote system through a webshell and need
 * to bind to a port, but the remote system is behind a firewall.
 * Deploy this tool, launch it with ./tcp-listen 4000-5000 and, from our
 * laptop, scan it (nmap -p 4000-5000).
 *
 * NOTE: This allocate a lot of file descriptor (cannot implement it with
 * libpcap as we're not sure to have enough privileges), so forks when out of
 * file descriptor.
 *
 * compile: clang -Wall -Wextra -o tcp-listen tcp-listen.c
 *
 * Author: N.Biscos Fri Mar 17 2017
 *
 * TODO: remote connection testing
 * TODO: command-line help
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h> 	/* select */
#include <stdint.h> 		/* uintxx_t */
#include <libgen.h>		/* basename */
#include <limits.h>		/* USHRT_MAX */
#include <ctype.h>		/* isdigit */
#include <string.h> 		/* memset */
#include <sys/types.h>
#include <sys/socket.h>		/* socket, bind, listen, accept */
#include <netinet/in.h>		/* struct sockaddr_in */
#include <unistd.h>		/* close */
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#ifndef GLOBAL_TMOUT
#define GLOBAL_TMOUT 30
#endif

static
int debug = 0;

/******************************************************************************\
				 ports handling
\******************************************************************************/
#define foreach_port(startport, port)				\
	for (port = startport; port > 0; ++ port)		\
		/* port > 0 to avoid ushort rotation */		\
		if (ports_bitmap[port/8] & (1<<(port%8)))

#define PORT_BITMAP_SIZE (USHRT_MAX + 1) / 8

uint8_t ports_bitmap[PORT_BITMAP_SIZE];

static
void set_ports_bitmap(uint16_t port)
{
	ports_bitmap[port/8] |= (1<<(port % 8));
}

static
int parse_ports(char *str)
{
	char *ptr, *endptr;
	unsigned int port, lastport;
	int port_count = 0;
	int isrange = 0;

	lastport = 1; /* thx clang analyzer warning */
	ptr = str;
	while (*ptr != 0) {
		if (*ptr == '-') {
			isrange = 1;
			ptr ++;
		} else if (*ptr == ',') {
			ptr ++;
		} else if (isdigit(*ptr)) {
			port = strtoul(ptr, &endptr, 10);
			ptr = endptr;
			if (port == 0 || port > USHRT_MAX)
				return -1; /* invalid port */
			if (isrange) {
				unsigned int p;
				for (p = lastport ; p < port ; ++ p) {
					set_ports_bitmap(p);
					port_count ++;
				}
			}
			lastport = port;
			isrange = 0;
			set_ports_bitmap(port);
			port_count ++;
		} else {
			return -2; /* invalid symbol */
			ptr ++;
		}
	}
	return port_count;
}

/******************************************************************************\
				     utils
\******************************************************************************/
static
void *xmalloc(size_t size)
{
	void *buf;
	buf = malloc(size);
	if (buf == NULL)
		abort();
	return buf;
}

/******************************************************************************\
				   ports list
\******************************************************************************/
/* taken from kernel list.h */
struct sockfd_list {
	struct sockfd_list *next;
	struct sockfd_list *prev;
	int sockfd;
};

#define sockfd_list_init(head)					\
	do {							\
		(head)->prev = head;				\
		(head)->next = head;				\
	} while (0)

#define sockfd_list_foreach(pos, n, head)			\
	for (pos = (head)->next, n = pos->next;			\
		pos != (head);					\
		pos = n, n = pos->next)

#define sockfd_list_add(head, sockfd)				\
	do {							\
		struct sockfd_list *new, *prev, *next;		\
		new = xmalloc(sizeof(struct sockfd_list));	\
		new->sockfd = (sockfd);				\
		prev = (head)->prev;				\
		next = (head);					\
		next->prev = new;				\
		new->next = next;				\
		new->prev = prev;				\
		prev->next = new;				\
	} while (0)

#define sockfd_list_remove(head, tmp)				\
	do {							\
		(tmp)->next->prev = (tmp)->prev;		\
		(tmp)->prev->next = (tmp)->next;		\
	} while (0)

#define sockfd_list_cleanup(head)				\
	do {							\
		struct sockfd_list *pos, *n;			\
		for (pos = (head)->next, n = pos->next;		\
			pos != (head);				\
			pos = n, n = pos->next) {		\
			sockfd_list_remove((head), pos);	\
			free(pos);				\
		}						\
	} while (0)

/******************************************************************************\
				  socket stuff
\******************************************************************************/
static
int _bind(int sockfd, uint16_t port)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htons(INADDR_ANY);
	if (bind(sockfd, (struct sockaddr *)&addr,
		sizeof(struct sockaddr_in)) == -1) {
		if (debug)
			perror("bind");
		return -1;
	}

	return 0;
}

static
int listen_port(uint16_t port)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("socket");
		return -1;
	}

	if (_bind(sockfd, port) == -1)
		goto error;

	if (listen(sockfd, 5) == -1) {
		perror("listen");
		goto error;
	}

	return sockfd;
error:
	if (close(sockfd) == -1)
		perror("close");
	return -1;
}

static
int _accept(int sockfd)
{
	int csockfd;

	/* FIXME: show our remote IP address in debug mode to determine if
	 * there are NAT rules */
	if ((csockfd = accept(sockfd, NULL, NULL)) == -1)
		return -1;

	if (close(csockfd) == -1)
		perror("close");
	return 0;
}

static
int parallel_accept(struct sockfd_list *sockfd_list)
{
	fd_set sockfd_set;
	struct sockfd_list *tmp, *pos;
	struct timeval tmout;
	int sockfd_max;
	int closed_count = 0;
	int ready;

	tmout.tv_sec = 1;
	tmout.tv_usec = 0;

	FD_ZERO(&sockfd_set);
	sockfd_max = 0;
	sockfd_list_foreach(pos, tmp, sockfd_list) {
		if (pos->sockfd > sockfd_max)
			sockfd_max = pos->sockfd;
		FD_SET(pos->sockfd, &sockfd_set);
	}

	ready = select(sockfd_max + 1, &sockfd_set, NULL, NULL, &tmout);
	switch (ready) {
	case -1:
		return -1;
	case 0:
		return 0;
	}

	sockfd_list_foreach(pos, tmp, sockfd_list) {
		if (FD_ISSET(pos->sockfd, &sockfd_set)
			&& _accept(pos->sockfd) != -1) {
			closed_count ++;
			/* immediately close this socket so that nobody can
			 * connect again and mess up with close_count */
			close(pos->sockfd);
			sockfd_list_remove(sockfd_list, pos);
			free(pos);
		}
	}
	return closed_count;
}

/******************************************************************************\
				timeout handling
\******************************************************************************/
static volatile
sig_atomic_t tmout = 0;

/* FIXME: this should be < 127 */
static volatile
sig_atomic_t children_count = 0;

static
void hdlr(int signum)
{
	int status, serrno;
	pid_t pid;

	switch (signum) {
	case SIGCHLD:
		/* errno can be modified by waitpid() */
		serrno = errno;

		while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
			children_count --;

		if (pid == -1 && errno != ECHILD) {
			 /* FIXME: what can we do in this case??? */
		}

		/* restore */
		errno = serrno;
		break;
	case SIGALRM:
		tmout = 1;
		break;
	}
}

static
int install_signal_handlers(void)
{
	struct sigaction sa;

	/* restart system call when interrupted. Useful for waitpid() that is
	 * interrupted when SIGALRM is sent again */
	sa.sa_flags = SA_RESTART;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = hdlr;

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}

	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}
	return 0;

}

static
int ignore_alarm(void)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;

	if (sigaction(SIGALRM, &sa, NULL) == -1) {
		perror("sigaction");
		return -1;
	}
	return 0;
}

static
int reap_all_children(void)
{
	sigset_t set;

	sigemptyset(&set);
	while (children_count > 0) {
		if (sigsuspend(&set) == -1 && errno != EINTR) {
			perror("sigsuspend");
			return -1;
		}
		if (tmout != 0) {
			/* ignore SIGALRM for this process */
			ignore_alarm();
			/* resend signal */
			kill(0, SIGALRM);
			/* mark tmout has handled */
			tmout = 0;
		}
	}
	return 0;
}

/******************************************************************************\
			   subprocesses communication
\******************************************************************************/
#define MSG_SIZE sizeof(uint16_t)
static
int send_lastport(int fd, uint16_t port)
{
	ssize_t nwrote;

	while ((((nwrote = write(fd, &port, MSG_SIZE)) == -1)
		/* resend if interrupted */
		&& errno == EINTR)
		/* resend all message if truncated */
		|| nwrote != MSG_SIZE);

	if (nwrote == -1) {
		perror("write");
		return -1;
	}

	/* send sync to father */
	if (close(fd) == -1) {
		perror("close(readyfd");
	}
	return 0;
}

static
int recv_lastport(int fd, uint16_t *port)
{
	ssize_t nread;

	while ((((nread = read(fd, port, MSG_SIZE)) == -1)
		/* reread if interrupted */
		&& errno == EINTR)
		/* reread if truncated */
		|| nread != MSG_SIZE);

	if (nread == -1) {
		perror("read");
		return -1;
	}

	if (close(fd) == -1) {
		perror("close");
	}
	return 0;
}

/******************************************************************************\
				  subprocesses
\******************************************************************************/
static
int handle_ports(uint16_t startport, int lastportfd, int max_fd)
{
	int sockfd;
	struct sockfd_list sockfd_list;
	uint16_t port;
	int listen_count = 0;

	sockfd_list_init(&sockfd_list);

	/* create as many sockets as possible */
	foreach_port(startport, port) {
		/* cannot open more fd in this process */
		if (max_fd == 0)
			break;

		if ((sockfd = listen_port(port)) == -1) {
			/* cannot do much here... */
			continue;
		}

		sockfd_list_add(&sockfd_list, sockfd);
		listen_count ++;
		max_fd --;
	}

	/* send to parent process info about last port we can listen to */
	if (send_lastport(lastportfd, port) == -1) {
		sockfd_list_cleanup(&sockfd_list);
		_exit(EXIT_FAILURE);
	}

	/* keep on listening whilst there is open ports, or timeout hasn't
	 * expire */
	while (listen_count > 0 && tmout == 0) {
		int closed_count;
		/* send SYN/ACK and FIN/ACK for all SYN received */
		closed_count = parallel_accept(&sockfd_list);
		if (closed_count == -1)
			continue;
		listen_count -= closed_count;
	}

	sockfd_list_cleanup(&sockfd_list);
	return 0;
}

static
int spawn_child(uint16_t startport, long max_fd_per_child)
{
	pid_t pid;
	/* communication pipe */
	int pfd[2];

	if (pipe(pfd) == -1) {
		perror("pipe");
		return -1;
	}

	pid = fork();
	switch (pid) {
	case -1:
		perror("fork");
		/* FIXME: retry? */
		return -1;
	case 0:
		close(pfd[0]);
		handle_ports(startport, pfd[1], max_fd_per_child);
		_exit(EXIT_SUCCESS);
	default:
		children_count ++;
		close(pfd[1]);
		break;
	}
	return pfd[0];
}

static
int create_subprocesses(long child_count, long max_fd_per_child)
{
	int i, fd;
	uint16_t startport;

	startport = 1;

	for (i = 0; i < child_count; i ++) {
		/* spawn a process that handle ports from startport up to
		 * max_fd_per_child ports */
		fd = spawn_child(startport, max_fd_per_child);

		if (fd == -1)
			continue;

		/* get last port handled by child */
		if (recv_lastport(fd, &startport) == -1)
			return -1;
	}
	return 0;
}

/******************************************************************************\
				   sysconfig
\******************************************************************************/
static
long get_max_children(void)
{
	long max_children;
	max_children = sysconf(_SC_CHILD_MAX);
	if (max_children == -1)
		max_children = _POSIX_CHILD_MAX;
	return max_children;
}

static
long get_max_fd(void)
{
	long max_fd;
	max_fd = sysconf(_SC_OPEN_MAX);
	if (max_fd == -1)
		max_fd = _POSIX_OPEN_MAX;
	return max_fd;
}

/******************************************************************************\
				      main
\******************************************************************************/
int main(int argc, char **argv)
{
	int ports_count;
	long child_count;
	long max_fd_per_child;
	long max_children;

	if (argc != 2) {
		fprintf(stderr, "Syntax: %s ports\n", basename(argv[0]));
		return EXIT_FAILURE;
	}

	if ((ports_count = parse_ports(argv[1])) < 0)
		return EXIT_FAILURE;

	/* remove 10 fd for stdin, stdout, etc. and sync pipes */
	max_fd_per_child = get_max_fd() - 10;

	/* check that system is not higher than FD_SETSIZE */
	max_fd_per_child = (max_fd_per_child < FD_SETSIZE) ? max_fd_per_child
		: FD_SETSIZE;

	child_count = ports_count / max_fd_per_child + 1;

	max_children = get_max_children();

	if (child_count >= max_children) {
		fprintf(stderr, "Cannot open so much sockets! Max %ld\n",
			max_fd_per_child * max_children);
		return EXIT_FAILURE;
	}

	if (install_signal_handlers() == -1)
		return EXIT_FAILURE;

	create_subprocesses(child_count, max_fd_per_child);

	/* alarm is not preserved across fork() */
	alarm(GLOBAL_TMOUT);
	if (reap_all_children() == -1)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}
