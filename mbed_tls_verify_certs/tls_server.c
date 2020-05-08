#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* mbedtls headers */
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/error.h"

#define BUFFER_SIZE 4096
#define MBEDTLS_ERROR_BUFFER_SIZE 1024

static void debug_handler (void *ctx, int level, const char *file, int line, const char *str)
{
	fprintf((FILE*) ctx, "%s:%d: [%d] %s", file, line, level, str);
	fflush((FILE*) ctx);
}

int main (int argc, char *argv[])
{
	int ret, exit = 1;
	unsigned char response[] = "HTTP/1.0 200 OK\r\n\r\nYou did it!\r\n";
	unsigned char *buffer;
	int len;
	char mbedtls_error[MBEDTLS_ERROR_BUFFER_SIZE];

	unsigned char ip [16];
	size_t ip_len;
	char ip_str[INET6_ADDRSTRLEN];

	mbedtls_net_context s;
	mbedtls_net_context conn_s;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_x509_crt server;
	mbedtls_pk_context pkey;

	/* Usage */
	if (argc != 2) {
		printf("Usage: %s [Port]\n", argv[0]);
		return 0;
	}

	/* Allocate buffer */
	buffer = malloc(BUFFER_SIZE);
	assert(buffer);

	/* 
	 * Initialize SSL data structures 
	 */

	mbedtls_net_init(&s);
	mbedtls_net_init(&conn_s);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_x509_crt_init(&ca);
	mbedtls_x509_crt_init(&server);
	mbedtls_pk_init(&pkey);

	/* 
	 * Load CA and server certificates, and server key
	 */

	/* Load CA & server certs */
	if ((ret = mbedtls_x509_crt_parse_file(&ca, "certs/CA.pem")) ||
			(ret = mbedtls_x509_crt_parse_file(&server, "certs/Server.pem"))) {
		fprintf(stderr, "mbedtls_x509_crt_parse_file failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* Load server key */
	if ((ret = mbedtls_pk_parse_keyfile(&pkey, "certs/Server.key", NULL))) {
		fprintf(stderr, "mbedtls_pk_parse_keyfile failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* 
	 * Set up initial SSL State
	 */

	/* Seed PRNG */
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
					mbedtls_entropy_func,
					&entropy,
					NULL,
					0))) {
		fprintf(stderr, "mbedtls_ctr_drbg_seed failed (%d)\n", ret );
		goto free_and_exit;
	}

	/* Get SSL config defaults */
	if ((ret = mbedtls_ssl_config_defaults(&conf,
					MBEDTLS_SSL_IS_SERVER,
					MBEDTLS_SSL_TRANSPORT_STREAM,
					MBEDTLS_SSL_PRESET_DEFAULT))) {
		fprintf(stderr, "mbedtls_ssl_config_defaults failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* Set Server cert */
	if ((ret = mbedtls_ssl_conf_own_cert(&conf, &server, &pkey))) {
		fprintf(stderr, "mbedtls_ssl_own_cert failed (%d)\n", ret);
		goto free_and_exit;
	}

	/* Require cert verification */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	/* 
	 * Add CA chain to SSL config, with 3rd param (Certificate Revocation
	 * List) ignored
	 */
	mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);

	/* Set PRNG and debug functions */
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, debug_handler, stderr);

	/* Setup SSL */
	if (mbedtls_ssl_setup(&ssl, &conf)) {
		fprintf(stderr, "mbedtls_ssl_setup failed\n");
		goto free_and_exit;
	}

	/* Bind TCP */
	if ((ret = mbedtls_net_bind(&s, NULL, argv[1], MBEDTLS_NET_PROTO_TCP))) {
		fprintf(stderr, "mbedtls_net_bind failed\n");
		goto free_and_exit;
	}

	/*
	 * Server loop
	 */
	for (;;) {
		/* Reset state */
		mbedtls_net_free(&conn_s);
		mbedtls_ssl_session_reset(&ssl);

		/* TCP accept */
		if ((ret = mbedtls_net_accept(&s, &conn_s, ip, 16, &ip_len))) {
			fprintf(stderr, "mbedtls_net_accept failed (%d)\n", ret);
			continue;
		}

		/* TODO: print client IP */
		if (ip_len == 4)
			inet_ntop(AF_INET, ip, ip_str, INET6_ADDRSTRLEN);
		else
			inet_ntop(AF_INET6, ip, ip_str, INET6_ADDRSTRLEN);

		printf("Connection from %s\n", ip_str);

		/* Set TCP socket I/O functions to mbedtls_net_send/recv */
		mbedtls_ssl_set_bio(&ssl, &conn_s, mbedtls_net_send, mbedtls_net_recv, NULL);

		/* SSL Handshake */
		while((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				mbedtls_strerror(ret, mbedtls_error, MBEDTLS_ERROR_BUFFER_SIZE);
				fprintf(stderr, "mbedtls_ssl_handshake failed: %s\n", mbedtls_error);
				continue;
			}
		}

		/* Read request */
		bzero(buffer, BUFFER_SIZE);
		len = BUFFER_SIZE;
		
		ret = mbedtls_ssl_read(&ssl, buffer, len);
		switch (ret) {
			case MBEDTLS_ERR_SSL_WANT_READ:
			case MBEDTLS_ERR_SSL_WANT_WRITE:
			case 0:
				break;
			case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
				printf("Connection closed by peer\n");
				continue;
			default: 
				if (ret < 0) {
					mbedtls_strerror(ret, mbedtls_error, MBEDTLS_ERROR_BUFFER_SIZE);
					fprintf(stderr, "mbedtls_ssl_read failed: %s\n", mbedtls_error);
					goto free_and_exit;
				}
		}

		/* Send response */
		len = sizeof(response);
		while ((ret = mbedtls_ssl_write(&ssl, response, len)) <= 0) {
			if (ret) {
				fprintf(stderr, "write failed (%d)\n", ret);
				goto free_and_exit;
			}
		}

		/* Close connection */
		mbedtls_ssl_close_notify(&ssl);
	}

free_and_exit:
	free(buffer);
	mbedtls_x509_crt_free(&ca);
	mbedtls_x509_crt_free(&server);
	mbedtls_net_free(&s);
	mbedtls_net_free(&conn_s);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return exit;
}
