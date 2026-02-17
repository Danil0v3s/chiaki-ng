// SPDX-License-Identifier: LicenseRef-AGPL-3.0-only-OpenSSL

#include <chiaki/remote/holepunch.h>

#include <string.h>

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_list_devices(
	const char* psn_oauth2_token,
	ChiakiHolepunchConsoleType console_type, ChiakiHolepunchDeviceInfo** devices,
	size_t* device_count, ChiakiLog *log)
{
	(void)psn_oauth2_token;
	(void)console_type;
	(void)log;
	if(devices)
		*devices = NULL;
	if(device_count)
		*device_count = 0;
	return CHIAKI_ERR_UNKNOWN;
}

CHIAKI_EXPORT void chiaki_holepunch_free_device_list(ChiakiHolepunchDeviceInfo** devices)
{
	if(devices)
		*devices = NULL;
}

CHIAKI_EXPORT ChiakiHolepunchRegistInfo chiaki_get_regist_info(ChiakiHolepunchSession session)
{
	(void)session;
	ChiakiHolepunchRegistInfo info;
	memset(&info, 0, sizeof(info));
	return info;
}

CHIAKI_EXPORT void chiaki_get_ps_selected_addr(ChiakiHolepunchSession session, char *ps_ip)
{
	(void)session;
	if(ps_ip)
		ps_ip[0] = '\0';
}

CHIAKI_EXPORT uint16_t chiaki_get_ps_ctrl_port(ChiakiHolepunchSession session)
{
	(void)session;
	return 0;
}

CHIAKI_EXPORT chiaki_socket_t *chiaki_get_holepunch_sock(ChiakiHolepunchSession session, ChiakiHolepunchPortType type)
{
	(void)session;
	(void)type;
	return NULL;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_generate_client_device_uid(char *out, size_t *out_size)
{
	static const char hex[] = "0123456789ABCDEF";
	uint8_t rnd[16];
	size_t i;

	if(!out_size)
		return CHIAKI_ERR_INVALID_DATA;
	if(*out_size < CHIAKI_DUID_STR_SIZE || !out)
	{
		*out_size = CHIAKI_DUID_STR_SIZE;
		return CHIAKI_ERR_BUF_TOO_SMALL;
	}

	memcpy(out, DUID_PREFIX, strlen(DUID_PREFIX));

	if(chiaki_random_bytes_crypt(rnd, sizeof(rnd)) != CHIAKI_ERR_SUCCESS)
		return CHIAKI_ERR_UNKNOWN;

	for(i = 0; i < sizeof(rnd); i++)
	{
		out[strlen(DUID_PREFIX) + i * 2] = hex[rnd[i] >> 4];
		out[strlen(DUID_PREFIX) + i * 2 + 1] = hex[rnd[i] & 0x0f];
	}
	out[CHIAKI_DUID_STR_SIZE - 1] = '\0';
	*out_size = CHIAKI_DUID_STR_SIZE;
	return CHIAKI_ERR_SUCCESS;
}

CHIAKI_EXPORT ChiakiHolepunchSession chiaki_holepunch_session_init(const char* psn_oauth2_token, ChiakiLog *log)
{
	(void)psn_oauth2_token;
	(void)log;
	return NULL;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_session_create(ChiakiHolepunchSession session)
{
	(void)session;
	return CHIAKI_ERR_UNINITIALIZED;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_session_start(
	ChiakiHolepunchSession session, const uint8_t* console_uid,
	ChiakiHolepunchConsoleType console_type)
{
	(void)session;
	(void)console_uid;
	(void)console_type;
	return CHIAKI_ERR_UNINITIALIZED;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_upnp_discover(ChiakiHolepunchSession session)
{
	(void)session;
	return CHIAKI_ERR_UNINITIALIZED;
}

CHIAKI_EXPORT ChiakiErrorCode holepunch_session_create_offer(ChiakiHolepunchSession session)
{
	(void)session;
	return CHIAKI_ERR_UNINITIALIZED;
}

CHIAKI_EXPORT ChiakiErrorCode chiaki_holepunch_session_punch_hole(
	ChiakiHolepunchSession session, ChiakiHolepunchPortType port_type)
{
	(void)session;
	(void)port_type;
	return CHIAKI_ERR_UNINITIALIZED;
}

CHIAKI_EXPORT void chiaki_holepunch_main_thread_cancel(ChiakiHolepunchSession session, bool stop_thread)
{
	(void)session;
	(void)stop_thread;
}

CHIAKI_EXPORT void chiaki_holepunch_session_fini(ChiakiHolepunchSession session)
{
	(void)session;
}
