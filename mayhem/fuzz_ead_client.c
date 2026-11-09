/*
 * In-process harness for ImmortalWrt's ead-client (Emergency Access Daemon client): the replies a
 * device sends over UDP during ping -> prime -> SRP exchange -> authenticated command. The client's own
 * source is compiled into this file; each input is one reply datagram, queued on a loopback socket and
 * consumed by the client's real send_packet()/handle_*() code for the stage its type field selects.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fuzz_util.h"

#define main ead_client_main
#include "package/network/services/ead/src/ead-client.c"
#undef main

static int peer = -1;
static struct sockaddr_in client_addr;

static const unsigned char fixed_key[40] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x00, 0x00, 0x10, 0x00, 0x55, 0xaa, 0x33, 0xcc,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct sockaddr_in a;
	socklen_t len = sizeof(a);
	(void)argc;
	(void)argv;
	if (!fuzz_sink_init())
		return -1;

	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	peer = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0 || peer < 0 || bind(s, (struct sockaddr *)&a, sizeof(a)) < 0 ||
	    bind(peer, (struct sockaddr *)&a, sizeof(a)) < 0)
		abort();
	getsockname(s, (struct sockaddr *)&client_addr, &len);
	len = sizeof(remote);
	getsockname(peer, (struct sockaddr *)&remote, &len);
	sockflags = fcntl(s, F_GETFL);
	return 0;
}

static void drain(int fd)
{
	char junk[2048];

	while (recv(fd, junk, sizeof(junk), MSG_DONTWAIT) >= 0)
		;
}

static void feed(const uint8_t *data, size_t size)
{
	drain(s);
	drain(peer);
	sendto(peer, data, size, 0, (struct sockaddr *)&client_addr, sizeof(client_addr));
}

static void reset_state(void)
{
	memset(msgbuf, 0, sizeof(msgbuf));
	msg->magic = htonl(EAD_MAGIC);
	nid = 0xffff;
	sid = 0;
	auth_type = EAD_AUTH_DEFAULT;
	timeout = 0;
	username = "mayhem";
	strcpy(password, "mayhem");
	memset(pw_salt, 0, sizeof(pw_salt));
	memset(&B, 0, sizeof(B));
	B.data = bbuf;
	tc = NULL;
	skey = NULL;
}

static int open_client(void)
{
	tcp = t_getpreparam(0);
	salt.len = 16;
	memset(saltbuf, 0x5a, salt.len);
	tc = t_clientopen(username, &tcp->modulus, &tcp->generator, &salt);
	return tc != NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t type;
	uint16_t node;
	int mode;

	fuzz_sink_reset();
	/* ead-client.c's receive loop does read(s, msgbuf, sizeof(msgbuf)) and drops anything shorter than
	 * struct ead_msg, so the client never sees a datagram outside this range */
	if (size < sizeof(struct ead_msg) || size > sizeof(msgbuf))
		return -1;

	memcpy(&type, data + offsetof(struct ead_msg, type), sizeof(type));
	memcpy(&node, data + offsetof(struct ead_msg, nid), sizeof(node));
	type = ntohl(type);
	node = ntohs(node);

	reset_state();
	switch (type) {
	case EAD_TYPE_PONG:
		feed(data, size);
		send_ping();
		reset_state();
		nid = node;
		feed(data, size);
		send_ping();
		break;
	case EAD_TYPE_PRIME:
		for (mode = EAD_AUTH_DEFAULT; mode <= EAD_AUTH_MD5; mode++) {
			reset_state();
			nid = node;
			auth_type = mode;
			feed(data, size);
			get_prime();
			if (tc)
				t_clientclose(tc);
		}
		break;
	case EAD_TYPE_SEND_B:
		reset_state();
		nid = node;
		auth_type = data[size - 1] & 1;
		if (!open_client())
			break;
		feed(data, size);
		if (send_a())
			send_auth();
		t_clientclose(tc);
		break;
	case EAD_TYPE_DONE_AUTH:
		nid = node;
		if (!open_client())
			break;
		B.len = 64;
		memset(bbuf, 0x37, B.len);
		bbuf[0] = 0x42;
		t_clientgenexp(tc);
		t_clientpasswd(tc, password);
		skey = t_clientgetkey(tc, &B);
		if (skey) {
			t_clientresponse(tc);
			feed(data, size);
			send_packet(EAD_TYPE_DONE_AUTH, handle_done_auth, 1);
		}
		t_clientclose(tc);
		break;
	case EAD_TYPE_RESULT_CMD: {
		/* the body is the plaintext command result; seal it with the session key so the
		 * client's decrypt/IV/SHA-1 checks pass and the fuzzer reaches the handler */
		static uint8_t pkt[sizeof(msgbuf)];
		size_t hdr = sizeof(struct ead_msg);
		size_t body = size - hdr;
		size_t room = sizeof(pkt) - hdr - sizeof(struct ead_msg_encrypted) - 64;
		struct ead_msg *m = (struct ead_msg *)pkt;

		if (body > room)
			body = room;
		memset(pkt, 0, sizeof(pkt));
		memcpy(pkt, data, hdr);
		memcpy(pkt + hdr + sizeof(struct ead_msg_encrypted), data + hdr, body);
		m->magic = htonl(EAD_MAGIC);
		nid = node;
		ead_set_key((unsigned char *)fixed_key);
		ead_encrypt_message(m, body);
		ead_set_key((unsigned char *)fixed_key);
		feed(pkt, hdr + ntohl(m->len));
		send_packet(EAD_TYPE_RESULT_CMD, handle_cmd_data, 1);
		break;
	}
	default:
		return -1;
	}
	return 0;
}
