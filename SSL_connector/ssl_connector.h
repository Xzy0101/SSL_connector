#pragma once

#ifndef SSL_CONNECTOR_H
#define SSL_CONNECTOR_H

#ifdef SSL_CONNECTOR_EXPORTS
#define SSL_CONNECTOR_API __declspec(dllexport)
#else
#define SSL_CONNECTOR_API __declspec(dllimport)
#endif

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif
	
	typedef struct ssl_cntr ssl_connector;

	SSL_CONNECTOR_API ssl_connector* ssl_connector_init(
		FILE* errlog);
	SSL_CONNECTOR_API int ssl_connector_connect(
		ssl_connector* conn,
		const char* nodename,
		int port,
		FILE* errlog);
	SSL_CONNECTOR_API int ssl_connector_listen(
		ssl_connector* conn,
		int serverport,
		const char* skeypem,
		const char* certpem,
		FILE* errlog);
	SSL_CONNECTOR_API ssl_connector* ssl_connector_accept(
		ssl_connector* serverconn,
		FILE* errlog);
	SSL_CONNECTOR_API int ssl_connector_write(
		ssl_connector* conn,
		const char* msg,
		int len);
	SSL_CONNECTOR_API int ssl_connector_read(
		ssl_connector* conn,
		char* buffer,
		int maxlen);
	SSL_CONNECTOR_API void ssl_connector_free(
		ssl_connector* conn);

#ifdef __cplusplus
}
#endif

#endif