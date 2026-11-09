/* Known-answer test for the EAD packet crypto (AES + SHA-1 sealing) used by ead-client. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "../package/network/services/ead/src/ead-crypt.c"

int main(void)
{
	unsigned char key[40], buf[256];
	struct ead_msg *msg = (struct ead_msg *)buf;
	struct ead_msg_cmd_data *cmd;
	const char *text = "hello\n";
	int i, n;

	for (i = 0; i < 32; i++)
		key[i] = i;
	memset(key + 32, 0, 8);
	key[34] = 0x10;

	memset(buf, 0, sizeof(buf));
	cmd = EAD_ENC_DATA(msg, cmd_data);
	cmd->done = 1;
	memcpy(cmd->data, text, strlen(text));

	ead_set_key(key);
	ead_encrypt_message(msg, sizeof(*cmd) + strlen(text));
	printf("sealed_len=%u\n", (unsigned)ntohl(msg->len));
	printf("sealed_head=");
	for (i = 0; i < 16; i++)
		printf("%02x", ((unsigned char *)EAD_DATA(msg, enc))[i]);
	printf("\n");

	ead_set_key(key);
	n = ead_decrypt_message(msg);
	cmd = EAD_ENC_DATA(msg, cmd_data);
	printf("opened_len=%d done=%d text=%.6s", n, n > 0 ? cmd->done : -1, n > 0 ? (char *)cmd->data : "");

	ead_set_key(key);
	((unsigned char *)EAD_DATA(msg, enc))[3] ^= 1;
	printf("tamper=%d\n", ead_decrypt_message(msg));
	return 0;
}
