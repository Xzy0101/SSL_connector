#include "ssl_connector.h"

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <openssl\ssl.h>
#include <openssl\err.h>

struct ssl_cntr{
	SOCKET socket;
	SSL_CTX* ctx;
	SSL* ssl;
};

struct addrinfo* wrapper_tcp_dns(const char* nodename, FILE* errlog);
int set_server_ctx(SSL_CTX* ctx, const char* skeypem, const char* certpem, FILE* errlog);
SOCKET socket_listen(int port, FILE* errlog);
void log_openssl(FILE* errlog);

ssl_connector* ssl_connector_init(FILE* errlog)
{
	/* Initialize WinSock */
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);    // Winsock version 2.2

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		fprintf(errlog, "WSAStartup failed with error: %d\n", err);
		return NULL;
	}

	/* Initialize OpenSSL */
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	ssl_connector* conn = calloc(1, sizeof(*conn));
	conn->ctx = SSL_CTX_new(TLSv1_2_method());    //only using TLS v1.2
	if (!conn->ctx) {
		fprintf(errlog, "Unable to create SSL context");
		log_openssl(errlog);
		WSACleanup();
		free(conn);
		return NULL;
	}
	return conn;
}

int ssl_connector_connect(ssl_connector* conn, const char * nodename, int port, FILE * errlog)
{
	if (conn == NULL) {
		fprintf(errlog, "ssl_connector_connect: conn NULL pointer\n");
		return -1;
	}

	int err;
	struct addrinfo *nodeaddr = NULL;
	struct sockaddr_in sin;
	ZeroMemory(&sin, sizeof(sin));

	nodeaddr = wrapper_tcp_dns(nodename, errlog);
	if (nodeaddr == NULL)
		return -1;

	for (struct addrinfo *next = nodeaddr; next != NULL; next = next->ai_next) {
		conn->ssl = SSL_new(conn->ctx);
		if (conn->ssl == NULL) {
			log_openssl(errlog);
			break;
		}
		memcpy(&sin, next->ai_addr, sizeof(sin));
		sin.sin_port = htons(port);
		conn->socket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (conn->socket == INVALID_SOCKET) {
			fprintf(errlog, "socket: Error %d\n", WSAGetLastError());
			break;
		}
		err = connect(conn->socket, (struct sockaddr*)(&sin), sizeof(sin));
		if (err == SOCKET_ERROR) {
			fprintf(errlog, "connect: Error %d\n", WSAGetLastError());
			closesocket(conn->socket);
			conn->socket = INVALID_SOCKET;
			continue;
		}
		SSL_set_fd(conn->ssl, conn->socket);
		err = SSL_connect(conn->ssl);
		if (err != 1) {
			log_openssl(errlog);
			shutdown(conn->socket, SD_BOTH);
			closesocket(conn->socket);
			SSL_free(conn->ssl);
			conn->ssl = NULL;
			continue;
		}
		freeaddrinfo(nodeaddr);
		return 0;
	}
	freeaddrinfo(nodeaddr);
	return -1;
}

int ssl_connector_listen(ssl_connector* conn, int serverport,
	const char* skeypem, const char* certpem, FILE* errlog)
{
	if (!conn) {
		fprintf(errlog, "ssl_connector_listen: conn NULL pointer\n");
		return -1;
	}
	if (conn->socket) {
		fprintf(errlog, "ssl_connector_listen: socket already created\n");
		return -1;
	}

	if (set_server_ctx(conn->ctx, skeypem, certpem, errlog) == -1)
		return -1;
	conn->socket = socket_listen(serverport, errlog);
	if (conn->socket == INVALID_SOCKET)
		return -1;

	return 0;
}

ssl_connector* ssl_connector_accept(ssl_connector* serverconn, FILE* errlog) {
	if (serverconn == NULL) {
		fprintf(errlog, "ssl_connector_accept: serverconn NULL pointer\n");
		return NULL;
	}
	if (serverconn->ctx == NULL) {
		fprintf(errlog, "ssl_connector_accept: context NULL pointer\n");
		return NULL;
	}
	if (serverconn->socket == INVALID_SOCKET) {
		fprintf(errlog, "ssl_connector_accept: invalid socket\n");
		return NULL;
	}

	ssl_connector* clientconn = calloc(1, sizeof(*clientconn));
	clientconn->socket = accept(serverconn->socket, NULL, NULL);
	if (clientconn->socket == INVALID_SOCKET) {
		fprintf(errlog, "accept: Error %d\n", WSAGetLastError());
		free(clientconn);
		return NULL;
	}
	clientconn->ssl = SSL_new(serverconn->ctx);
	if (!clientconn->ssl) {
		log_openssl(errlog);
		closesocket(clientconn->socket);
		free(clientconn);
		return NULL;
	}
	SSL_set_fd(clientconn->ssl, clientconn->socket);
	if (SSL_accept(clientconn->ssl) <= 0) {
		log_openssl(errlog);
		SSL_free(clientconn->ssl);
		closesocket(clientconn->socket);
		free(clientconn);
		return NULL;
	}
	return clientconn;
}

int ssl_connector_write(ssl_connector* conn, const char * msg, int len)
{
	return SSL_write(conn->ssl, msg, len);
}

int ssl_connector_read(ssl_connector* conn, char * buffer, int maxlen)
{
	return SSL_read(conn->ssl, buffer, maxlen);
}

void ssl_connector_free(ssl_connector* conn)
{
	if (conn == NULL)
		return;
	if (conn->socket != INVALID_SOCKET) {
		shutdown(conn->socket, SD_BOTH);
		closesocket(conn->socket);
	}
	if (conn->ssl != NULL)
		SSL_free(conn->ssl);
	if (conn->ctx) {
		SSL_CTX_free(conn->ctx);
		WSACleanup();
	}
	free(conn);
}

struct addrinfo * wrapper_tcp_dns(const char * nodename, FILE * errlog)
{
	/* get server address */
	int err = 0;
	struct addrinfo hint;
	struct addrinfo *res = NULL;
	ZeroMemory(&hint, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = IPPROTO_TCP;
	err = getaddrinfo(nodename, NULL, &hint, &res);
	if (err) {
		fprintf(errlog, "getaddrinfo: Error %d, server address: %s\n", err, nodename);
	}
	return res;
}

int set_server_ctx(SSL_CTX* ctx,const char* skeypem, const char* certpem, FILE* errlog) {
	SSL_CTX_set_ecdh_auto(ctx, 1);
	if (SSL_CTX_use_certificate_file(ctx, certpem, SSL_FILETYPE_PEM) <= 0) {
		log_openssl(errlog);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, skeypem, SSL_FILETYPE_PEM) <= 0) {
		log_openssl(errlog);
		return -1;
	}
	return 0;
}

SOCKET socket_listen(int port, FILE* errlog) {
	SOCKET s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		fprintf(errlog, "socket: Error %d\n", WSAGetLastError());
		return INVALID_SOCKET;
	}

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		fprintf(errlog, "bind: Error %d\n", WSAGetLastError());
		closesocket(s);
		return INVALID_SOCKET;
	}

	if (listen(s, SOMAXCONN) == SOCKET_ERROR) {
		fprintf(errlog, "listen: Error %d\n", WSAGetLastError());
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

void log_openssl(FILE* errlog) {
	int err = 0;
	const char *str = NULL;
	while (err = ERR_get_error()) {
		str = ERR_error_string(err, NULL);
		if (!str)
			return;
		fprintf(errlog, "%s\n", str);
	}
}