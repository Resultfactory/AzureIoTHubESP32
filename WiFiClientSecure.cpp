#ifdef __cplusplus
extern "C" {
#endif

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/dns.h"
#include "lwip/ip4_addr.h"
#include "lwip/netdb.h"
#include "mbedtls/debug.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
}
#endif
#include "WiFiClientSecure.h"

static const char *wcs = "WiFiClientSecure";

extern const uint8_t azure_root_cert_pem_start[] asm("_binary_azure_root_cert_pem_start");
extern const uint8_t azure_root_cert_pem_end[] asm("_binary_azure_root_cert_pem_end");

uint8_t WiFiClientSecure::idCount = 0;

WiFiClientSecure::WiFiClientSecure()
{
	id = idCount;
	idCount++;

	// AddressInformation defaults
	memset(&ai, 0, sizeof(ai));
	ai.family = AF_INET;
	ai.socktype = SOCK_STREAM;
	ai.protocol = IPPROTO_TCP;

	readTimeout = 5000;
	Init();

	TAGID = (char *)calloc(1, strlen(wcs) + 2);
	char *ids = (char *)calloc(1, sizeof(char) * 2);
	sprintf(ids, ":%d", id);
	strcpy(TAGID, wcs);
	strcat(TAGID, ids);
	ESP_LOGD(TAGID, "ID: %d", id);
}

uint8_t WiFiClientSecure::GetID(void)
{
	return id;
}

void WiFiClientSecure::Init(void)
{
	mbedtls_ssl_init(&_ssl);
	mbedtls_x509_crt_init(&_cacert);
	mbedtls_ctr_drbg_init(&_ctr_drbg);
	mbedtls_ssl_config_init(&_config);
	mbedtls_entropy_init(&_entropy);
}

uint8_t WiFiClientSecure::HostByName(const char *name, uint32_t *ipAddress)
{
	struct ip4_addr *ip4;
	struct hostent *hp;
	int ret = 0;

	hp = gethostbyname(name);
	if (!hp)
	{
		ESP_LOGE(TAGID, "Could not resolve hostname");
		return ret;
	}
	ip4 = (struct ip4_addr *)hp->h_addr;
	(*ipAddress) = ip4->addr;

	if (hostName == NULL)
	{
		size_t slen = strlen(name) + 1;
		hostName = (char *)malloc(slen);
		memcpy(hostName, name, slen);
		ESP_LOGV(TAGID, "slen: %d, name:%d %s, hostName:%d %s", slen, strlen(name), name, strlen(hostName), hostName);
	}
	return 1;
}

int WiFiClientSecure::SSLHandshake(void)
{
	int ret;

	while ((ret = mbedtls_ssl_handshake(&_ssl)) != 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			ESP_LOGE(TAGID, "mbedtls_ssl_handshake returned -0x%x", -ret);
			mbedtls_ssl_states s = (mbedtls_ssl_states)_ssl.state;
			ESP_LOGE(TAGID, "mbedtls_ssl_handshake state %d", s);
			break;
		}
	}
	return ret;
}

int WiFiClientSecure::ConnectTo(const char *name, uint16_t port)
{
	int ret = 0;

	if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, NULL, 0)) == 0)
	{
		int flags;

		ESP_LOGV(TAGID, "mbedtls_ctr_drbg_seed");

		ret = mbedtls_x509_crt_parse(&_cacert, azure_root_cert_pem_start, azure_root_cert_pem_end - azure_root_cert_pem_start);
		if (ret < 0)
		{
			ESP_LOGE(TAGID, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		}

		ESP_LOGI(TAGID, "Setting hostname for TLS session: %s", name);
		/* Hostname set here should match CN in server certificate */
		if ((ret = mbedtls_ssl_set_hostname(&_ssl, name)) == 0)
		{
			ESP_LOGI(TAGID, "Setting up the SSL/TLS structure...");

			if ((ret = mbedtls_ssl_config_defaults(
					 &_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) == 0)
			{
				// MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
				// a warning if CA verification fails but it will continue to
				// connect.
				// You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your
				// own code.
				mbedtls_ssl_conf_authmode(&_config, MBEDTLS_SSL_VERIFY_REQUIRED);
				mbedtls_ssl_conf_ca_chain(&_config, &_cacert, NULL);
				mbedtls_ssl_conf_rng(&_config, mbedtls_ctr_drbg_random, &_ctr_drbg);
				if (readTimeout > 0)
					mbedtls_ssl_conf_read_timeout(&_config, readTimeout);

				if ((ret = mbedtls_ssl_setup(&_ssl, &_config)) == 0)
				{
					mbedtls_net_init(&_server_fd);

					char portString[10];
					itoa(port, portString, 10);
					ESP_LOGI(TAGID, "Connecting to %s:%s...", name, portString);
					if ((ret = NetConnect(&_server_fd, name, portString, MBEDTLS_NET_PROTO_TCP)) == 0) // mbedtls_net_connect sets up
					{
						ESP_LOGI(TAGID, "Connected");

						mbedtls_net_set_nonblock(&_server_fd);
						mbedtls_ssl_set_bio(&_ssl, &_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

						ESP_LOGI(TAGID, "Performing the SSL/TLS handshake...");
						if ((ret = SSLHandshake()) == 0)
						{
							ESP_LOGI(TAGID, "Verifying peer X.509 certificate...");
							if ((flags = mbedtls_ssl_get_verify_result(&_ssl)) != 0)
							{
								char info[512];
								// In real life, we probably want to close connection if ret != 0
								ESP_LOGW(TAGID, "Failed to verify peer certificate");
								bzero(info, sizeof(info));
								mbedtls_x509_crt_verify_info(info, sizeof(info), "  ! ", flags);
								ESP_LOGW(TAGID, "%s", info);
								mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
								ESP_LOGW(TAGID, "%s", info);
							}
							else
								ESP_LOGI(TAGID, "Certificate verified");
						}
					}
					else
						ESP_LOGE(TAGID, "mbedtls_net_connect returned -%x", -ret);
				}
				else
					ESP_LOGE(TAGID, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
			}
			else
				ESP_LOGE(TAGID, "mbedtls_ssl_config_defaults returned %d", ret);
		}
		else
			ESP_LOGE(TAGID, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
		//}
		// else
		//	ESP_LOGE(TAGID, "mbedtls_x509_crt_parse returned -0x%x", -ret);
	}
	else
		ESP_LOGE(TAGID, "mbedtls_ctr_drbg_seed returned %d", ret);

	return ret;
}

int WiFiClientSecure::ConnectTo(ip4_addr *ip, uint16_t port)
{
	int ret = 0;

	// Init();
	// Moved init to function, hostbyname saves hostname in _ssl

	if ((ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, NULL, 0)) == 0)
	{
		int flags;

		ESP_LOGV(TAGID, "mbedtls_ctr_drbg_seed");

		ret = mbedtls_x509_crt_parse(&_cacert, azure_root_cert_pem_start, azure_root_cert_pem_end - azure_root_cert_pem_start);
		if (ret < 0)
		{
			ESP_LOGE(TAGID, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		}

		ESP_LOGI(TAGID, "Setting hostname for TLS session: %s", hostName);
		/* Hostname set here should match CN in server certificate */

		if ((ret = mbedtls_ssl_set_hostname(&_ssl, (const char *)hostName)) == 0)
		{
			ESP_LOGI(TAGID, "Setting up the SSL/TLS structure...");

			if ((ret = mbedtls_ssl_config_defaults(
					 &_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) == 0)
			{
				// MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it
				// will print
				// a warning if CA verification fails but it will continue to
				// connect.
				// You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your
				// own code.
				mbedtls_ssl_conf_authmode(&_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
				mbedtls_ssl_conf_ca_chain(&_config, &_cacert, NULL);
				mbedtls_ssl_conf_rng(&_config, mbedtls_ctr_drbg_random, &_ctr_drbg);
				if (readTimeout > 0)
					mbedtls_ssl_conf_read_timeout(&_config, readTimeout);

				if ((ret = mbedtls_ssl_setup(&_ssl, &_config)) == 0)
				{
					mbedtls_net_init(&_server_fd);

					ESP_LOGI(TAGID, "Connecting to %08x:%d...", ip->addr, port);
					if ((ret = NetConnect(&_server_fd, ip, port, MBEDTLS_NET_PROTO_TCP)) == 0)
					{
						ESP_LOGI(TAGID, "Connected");

						mbedtls_net_set_nonblock(&_server_fd);
						mbedtls_ssl_set_bio(&_ssl, &_server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

						ESP_LOGI(TAGID, "Performing the SSL/TLS handshake...");
						if ((ret = SSLHandshake()) == 0)
						{
							ESP_LOGI(TAGID, "Verifying peer X.509 certificate...");
							if ((flags = mbedtls_ssl_get_verify_result(&_ssl)) != 0)
							{
								char info[512];
								// In real life, we probably want to close connection if ret != 0
								ESP_LOGW(TAGID, "Failed to verify peer certificate");
								bzero(info, sizeof(info));
								mbedtls_x509_crt_verify_info(info, sizeof(info), "  ! ", flags);
								ESP_LOGW(TAGID, "%s", info);
								mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
								ESP_LOGW(TAGID, "%s", info);
							}
							else
								ESP_LOGI(TAGID, "Certificate verified");
						}
					}
					else
						ESP_LOGE(TAGID, "mbedtls_net_connect returned -%x", -ret);
				}
				else
					ESP_LOGE(TAGID, "mbedtls_ssl_setup returned -0x%x", -ret);
			}
			else
				ESP_LOGE(TAGID, "mbedtls_ssl_config_defaults returned %d", ret);
		}
		else
			ESP_LOGE(TAGID, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
		//}
		// else
		//	ESP_LOGE(TAGID, "mbedtls_x509_crt_parse returned -0x%x", -ret);
	}
	else
		ESP_LOGE(TAGID, "mbedtls_ctr_drbg_seed returned %d", ret);

	if (ret == 0 || ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
		return 1;
	else if (ret < 0)
		return 0;
	return ret;
}

void WiFiClientSecure::SetTimeout(unsigned long timeout)
{
	mbedtls_ssl_conf_read_timeout(&_config, (readTimeout = timeout));
}

int WiFiClientSecure::NetConnect(mbedtls_net_context *ctx, const char *host, const char *port, int proto)
{
	int ret;
	struct addrinfo hints, *addr_list, *cur;

	// Does Nothing! see mbedtls/port/net.c:77
	//	if ((ret = net_prepare()) != 0) {
	//		return (ret);
	//	}

	/* Do name resolution with both IPv6 and IPv4 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

	if (getaddrinfo(host, port, &hints, &addr_list) != 0)
	{
		return MBEDTLS_ERR_NET_UNKNOWN_HOST;
	}

	/* Try the sockaddrs until a connection succeeds */
	ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
	for (cur = addr_list; cur != NULL; cur = cur->ai_next)
	{
		ctx->fd = (int)socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
		if (ctx->fd < 0)
		{
			ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
			continue;
		}

		// save socket information
		ai.family = cur->ai_family;
		ai.socktype = cur->ai_socktype;
		ai.protocol = cur->ai_protocol;

		if (connect(ctx->fd, cur->ai_addr, cur->ai_addrlen) == 0)
		{
			// save address
			ai.addr = *cur->ai_addr;
			ai.addrlen = cur->ai_addrlen;
			ret = 0;
			break;
		}

		close(ctx->fd);
		ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
	}

	freeaddrinfo(addr_list);

	return ret;
}

int WiFiClientSecure::NetConnect(mbedtls_net_context *ctx, ip4_addr *host, uint16_t port, int proto)
{
	int ret;

	ctx->fd = (int)socket(ai.family, ai.socktype, ai.protocol);
	if (ctx->fd < 0)
		return MBEDTLS_ERR_NET_SOCKET_FAILED;

	struct sockaddr_in sock_addr;

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_addr.s_addr = 0;
	sock_addr.sin_port = 0;
	if ((ret = bind(ctx->fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr))) != 0)
	{
		ESP_LOGE(TAGID, "LWIP Bind Failed: 0x%x, socket: %d", ret, ctx->fd);
		return ret;
	}
	sock_addr.sin_addr.s_addr = host->addr;
	sock_addr.sin_port = htons(port);

	if (connect(ctx->fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == 0)
		return 0;

	ESP_LOGV(TAGID, "AddressInformation: fam: %d, sock: %d, proto: %d, addrlen: %d",
			 ai.family,
			 ai.socktype,
			 ai.protocol,
			 ai.addrlen);

	close(ctx->fd);

	return MBEDTLS_ERR_NET_CONNECT_FAILED;
}

uint8_t WiFiClientSecure::Connected()
{
	return _ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER;
}

void WiFiClientSecure::Stop(void)
{
	if (_server_fd.fd != -1)
	{
		mbedtls_ssl_session_reset(&_ssl);
		mbedtls_ssl_close_notify(&_ssl);

		mbedtls_net_free(&_server_fd);
		mbedtls_ssl_free(&_ssl);
		mbedtls_ssl_config_free(&_config);
		mbedtls_ctr_drbg_free(&_ctr_drbg);
		mbedtls_entropy_free(&_entropy);

		Init();
	}
}

size_t WiFiClientSecure::SSLWrite(const uint8_t *buf, size_t size)
{
	int ret;

	while ((ret = mbedtls_ssl_write(&_ssl, buf, size)) <= 0)
	{
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			ESP_LOGE(TAGID, "mbedtls_ssl_write returned -0x%x", -ret);
			Stop();
			break;
		}
	}
	return ret;
}

int WiFiClientSecure::SSLRead(uint8_t *buf, size_t size)
{
	int ret = mbedtls_ssl_read(&_ssl, buf, size);
	if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
	{
		ESP_LOGE(TAGID, "mbedtls_ssl_read returned -0x%x", -ret);
		Stop();
	}
	return ret;
}

int WiFiClientSecure::Available(void)
{
	int read,
		pend;

	read = SSLRead(NULL, 0);
	pend = mbedtls_ssl_get_bytes_avail(&_ssl);
	ESP_LOGV(TAGID, "read %d, has pending: %d, state %d", read, pend, _ssl.state);
	return pend;
}

/* Shorten 'file' from the whole file path to just the filename This is a bit
 * wasteful because the macros are compiled in with the full _FILE_ path in each
 * case.*/
void WiFiClientSecure::DebugPrint(void *ctx, int level, const char *file, int line, const char *str)
{
	char *file_sep;

	file_sep = rindex(file, '/');

	if (file_sep)
		file = file_sep + 1;

	switch (level)
	{
	case 1:
		ESP_LOGW(wcs, "%s:%d %s", file, line, str);
		break;
	case 2:
		ESP_LOGI(wcs, "%s:%d %s", file, line, str);
		break;
	case 3:
		ESP_LOGD(wcs, "%s:%d %s", file, line, str);
		break;
	case 4:
		ESP_LOGV(wcs, "%s:%d %s", file, line, str);
		break;

	default:
		ESP_LOGE(wcs, "Unexpected log level %d: %s", level, str);
		break;
	}
}

void WiFiClientSecure::Debug(uint8_t level)
{
	if (level > 0)
	{
		mbedtls_debug_set_threshold(level);
		mbedtls_ssl_conf_dbg(&_config, DebugPrint, NULL);
	}
	else
	{
		mbedtls_debug_set_threshold(0);
		mbedtls_ssl_conf_dbg(&_config, NULL, NULL);
	}
}

WiFiClientSecure::~WiFiClientSecure()
{
	Stop();
	free(TAGID);
}