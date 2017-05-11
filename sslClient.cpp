// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "sslClient.h"
#include "xlogging.h"

#include "openssl/ssl.h"
#include "internal/ssl_code.h"
#include "lwip/ip4_addr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_attr.h"

#include "WiFiClientSecure.h"
//static DRAM_ATTR WiFiClientSecure sslClient;
//static WiFiClientSecure *sslClientp = NULL;
static const char *TAG = "sslClient";
static WiFiClientSecure sslClient;

void sslClient_setTimeout(unsigned long timeout)
{
	ESP_LOGV(TAG, "setTimeout");
	sslClient.SetTimeout(timeout);
}

uint8_t sslClient_connected(void)
{
	ESP_LOGV(TAG, "connected");
	return sslClient.Connected();
}

static struct ip4_addr ip4;
static uint16_t ip4port;
int sslClient_connect(uint32_t ipAddress, uint16_t port)
{
	ESP_LOGV(TAG, "connect");
	ip4.addr = ipAddress;
	ip4port = port;
	//	vTaskDelay(100 / portTICK_RATE_MS);
	//	ESP_LOGV(TAG, "Connect ssl, Heap free: %d\n", esp_get_free_heap_size());//ssl estimate
	//	int ret = sslClient.connectTo(&ip4, port);
	//	ESP_LOGV(TAG, "Connect ssl, Heap free: %d\n", esp_get_free_heap_size());//ssl estimate
	return sslClient.ConnectTo(&ip4, port);
}

int sslClient_reconnect(void)
{
	ESP_LOGV(TAG, "reconnect");
	return sslClient.ConnectTo(&ip4, ip4port);
}

void sslClient_stop(void)
{
	ESP_LOGV(TAG, "stop");
	sslClient.Stop();
}

size_t sslClient_write(const uint8_t *buf, size_t size)
{
	ESP_LOGV(TAG, "write");
	return sslClient.SSLWrite(buf, size);
}

size_t sslClient_print(const char *str) //unused
{
	ESP_LOGV(TAG, "print %s", str);
	return 0;
	//	return sslClient.print(str);
}

int sslClient_read(uint8_t *buf, size_t size)
{
	ESP_LOGV(TAG, "read");
	return sslClient.SSLRead(buf, size);
}

int sslClient_available(void)
{
	ESP_LOGV(TAG, "available");
	return sslClient.Available();
}

uint8_t sslClient_hostByName(const char *hostName, uint32_t *ipAddress)
{
	ESP_LOGV(TAG, "hostByName");
	return sslClient.HostByName(hostName, ipAddress);
}

void sslClient_register(void)
{
}
