#include "UdpSocket.h"

namespace Wintun2socks {
	std::unordered_map<uint16, UdpSocket^> UdpSocket::m_socketmap;

	void UdpSocket::udp_recv_func(void* arg, udp_pcb* pcb, pbuf* p, const ip_addr_t* addr, u16_t port)
	{
		Platform::Array<uint8, 1>^ data;
		auto it = m_socketmap.find(pcb->remote_port);
		if (it == m_socketmap.end() || it->second->m_closed) {
			goto CLEANUP;
		}

		data = ref new Platform::Array<uint8, 1>(p->tot_len);
		if (pbuf_copy_partial(p, data->Data, p->tot_len, 0)) {
			goto CLEANUP;
		}
		it->second->OnReceive(it->second, data, addr->addr, port);
	CLEANUP:
		pbuf_free(p);
	}

	UdpSocket::UdpSocket(u32_t localAddr, u16_t localPort, udp_pcb* pcb) : pcb(pcb)
	{
		ip_addr_t localIpAddr = { localAddr };
		udp_connect(pcb, &localIpAddr, localPort);
		udp_recv(pcb, udp_recv_func, nullptr);

		RemoteAddr = pcb->local_ip.addr;
		RemotePort = pcb->local_port;

		m_socketmap[localPort] = this;
	}

	err_t UdpSocket::bind(u32_t localAddr, u16_t localPort, u32_t remoteAddr, u16_t remotePort)
	{
		auto it = m_socketmap.find(localPort);
		if (it != m_socketmap.end()) {
			if (it->second->m_closed) {
				m_socketmap.erase(localPort);
			}
			else {
				// There is an existing open socket
				return ERR_OK;
			}
		}
		auto pcb = udp_new();
		auto ret = udp_bind(pcb, IP_ADDR_ANY, remotePort);
		if (ret != ERR_OK) {
			return ret;
		}
		auto socket = ref new UdpSocket(localAddr, localPort, pcb);
		UdpSocket::OnPortAssociate(socket);
		return ERR_OK;
	}

	void UdpSocket::Deinit()
	{
		m_socketmap.clear();
	}

	u8_t UdpSocket::Send(const Platform::Array<uint8, 1>^ data)
	{
		if (m_closed) {
			return ERR_CLSD;
		}
		auto pbuf = pbuf_alloc(PBUF_TRANSPORT, data->Length, PBUF_RAM);
		return udp_send(pcb, pbuf);
	}

	void UdpSocket::Close()
	{
		if (m_closed) return;
		m_closed = true;
		udp_disconnect(pcb);
		udp_remove(pcb);
	}

	UdpSocket::~UdpSocket()
	{
		if (!m_closed) {
			Close();
		}
	}

}
