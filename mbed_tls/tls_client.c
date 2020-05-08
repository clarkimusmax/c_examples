/*
 * Simple mbedtls HTTP/S Client
 *
 * Based on this: https://github.com/ARMmbed/mbedtls/blob/development/programs/ssl/ssl_client1.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mbed headers */
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#define RESP_BUF_SIZE 2048
#define MBEDTLS_ERROR_BUFFER_SIZE 1024

static void debug_handler (void *ctx, int level, const char *file, int line, const char *str)
{
	fprintf((FILE*) ctx, "%s:%d: [%d] %s", file, line, level, str);
	fflush((FILE*) ctx);
}

int main (int argc, char *argv[])
{
	int ret, exit = 1;
	unsigned char request[] = "GET / HTTP/1.0\r\n\r\n";
	unsigned char *response;
	int len;
	char mbedtls_error[MBEDTLS_ERROR_BUFFER_SIZE];

	mbedtls_net_context s;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;

	/* Usage */
	if (argc != 3) {
		printf("Usage: %s [IPv4 Address] [Port]\n", argv[0]);
		return 0;
	}

	/* Initialize SSL */
	mbedtls_net_init(&s);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	/* Seed PRNG */
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
					mbedtls_entropy_func,
					&entropy,
					NULL,
					0);
	if (ret != 0) {
		fprintf(stderr, "mbedtls_ctr_drbg_seed failed (%d)\n", ret );
	        goto free_and_exit;
	}

	/* TCP Connect */
	ret = mbedtls_net_connect(&s, argv[1], argv[2], MBEDTLS_NET_PROTO_TCP);
	if (ret != 0) {
		fprintf(stderr, "mbedtls_net_connect failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* Configure SSL */
	ret = mbedtls_ssl_config_defaults(&conf,
					MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		fprintf(stderr, "mbedtls_ssl_config_defaults failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* Don't check certs (not secure!) */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

	/* Set PRNG and debug functions */
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, debug_handler, stderr);

	/* Setup SSL */
	if (mbedtls_ssl_setup(&ssl, &conf)) {
		fprintf(stderr, "mbedtls_ssl_setup failed\n");
		goto free_and_exit;
	}

	/* Set TCP socket I/O functions to mbedtls_net_send/recv */
	mbedtls_ssl_set_bio(&ssl, &s, mbedtls_net_send, mbedtls_net_recv, NULL);

	/* SSL Handshake */
	while((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			mbedtls_strerror(ret, mbedtls_error, MBEDTLS_ERROR_BUFFER_SIZE);
			fprintf(stderr, "mbedtls_ssl_handshake failed: %s\n", mbedtls_error);
			goto free_and_exit;
		}
	}

	/* Put GET request in buffer */
	len = strlen((char*)request);

	/* Send it */
	while ((ret = mbedtls_ssl_write(&ssl, request, len)) <= 0) {
		if (ret) {
			fprintf(stderr, "write failed (%d)\n", ret);
			goto free_and_exit;
		}
	}

	/* Get mem for resposne */
	response = malloc(RESP_BUF_SIZE);
	if (!response) {
		fprintf(stderr, "No memory\n");
		goto free_and_exit;;
	}

	/* Get response */
	do {
		len = RESP_BUF_SIZE-1;
		memset(response, '\0', len);

		ret = mbedtls_ssl_read(&ssl, response, len);

		/* Continue trying to recv */
		if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
			ret ==  MBEDTLS_ERR_SSL_WANT_WRITE )
			continue;

		/* All done, exit loop */
		if (ret == 0)
			break;

		/* Connection gone, exit loop */
		if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			printf("Connection closed by peer\n");
			break;
		}

		/* Encountered error, exit loop */
		if (ret < 0) {
			mbedtls_strerror(ret, mbedtls_error, MBEDTLS_ERROR_BUFFER_SIZE);
			fprintf(stderr, "mbedtls_ssl_read failed: %s\n", mbedtls_error);
			free(response);
			goto free_and_exit;
		}

		/* Print it */
		printf("%s", response);
	} while (1);

	/* Free response buffer */
	free(response);

	/* Close connection */
	mbedtls_ssl_close_notify(&ssl);

	/* Exit success */
	exit ^= exit;

free_and_exit:
	mbedtls_net_free(&s);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return exit;
}
