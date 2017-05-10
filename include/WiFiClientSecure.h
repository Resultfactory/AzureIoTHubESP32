#ifndef WIFICLIENTSECURE_H_
#define WIFICLIENTSECURE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "lwip/ip4_addr.h"
#include "lwip/ip_addr.h"
#include "lwip/sockets.h"

#include "mbedtls/net.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

typedef struct AddressInformation
{
	int family, socktype, protocol;
	struct sockaddr addr;
	socklen_t addrlen;
} AddressInformation;

class WiFiClientSecure
{
  public:
	WiFiClientSecure(bool blocking);
	WiFiClientSecure();
	~WiFiClientSecure();

	int ConnectTo(ip4_addr *ip, uint16_t port);
	void SetTimeout(unsigned long timeout);
	uint8_t Connected();
	void Stop(void);
	size_t SSLWrite(const uint8_t *buf, size_t size);
	int SSLRead(uint8_t *buf, size_t size);
	int Available(void);
	uint8_t HostByName(const char *hostName, uint32_t *ipAddress);
	uint8_t GetID(void);
	void Debug(uint8_t level);

  private:
	mbedtls_net_context _server_fd;
	mbedtls_ctr_drbg_context _ctr_drbg;
	mbedtls_entropy_context _entropy;
	mbedtls_ssl_config _config;
	mbedtls_ssl_context _ssl;
	mbedtls_x509_crt _cacert;

	char *hostName = NULL;
	AddressInformation ai;
	uint32_t readTimeout = 0;
	bool blocking;
	char *TAGID;
	static uint8_t idCount;
	uint8_t id;

	void Init(void);
	int NetConnect(mbedtls_net_context *ctx, const char *host, const char *port, int proto);
	int NetConnect(mbedtls_net_context *ctx, ip4_addr *host, uint16_t port, int proto);
	int SSLHandshake(void);
	static void DebugPrint(void *ctx, int level, const char *file, int line, const char *str);
};

#ifdef __cplusplus
}
#endif
#endif // !WIFICLIENTSECURE_H_